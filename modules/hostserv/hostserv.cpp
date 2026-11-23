// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2003-2026 Anope Contributors
// Copyright (C) 2026 Warden Contributors
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// Based on the original code of Epona by Lara
// Based on the original code of Services by Andy Church
//
// SPDX-License-Identifier: GPL-2.0-only

#include "module.h"

class HostServCore final
	: public Module
{
	Reference<BotInfo> HostServ;

	// The vhost HostServ last applied to a user, so it can be removed again
	// when they log out without touching a vhost from anywhere else
	// (anope/anope#570). HS ON and HS OFF set and clear it by name.
	PrimitiveExtensibleItem<Warden::string> applied;

	void Apply(User *u, const NickAlias *na)
	{
		IRCD->SendVHost(u, na->GetVHostIdent(), na->GetVHostHost());

		u->vhost = na->GetVHostHost();
		u->UpdateHost();

		if (IRCD->CanSetVIdent && !na->GetVHostIdent().empty())
			u->SetVIdent(na->GetVHostIdent());
		applied.Set(u, na->GetVHostHost());

		if (HostServ)
		{
			u->SendMessage(HostServ, _("Your vhost of \002%s\002 is now activated."),
				na->GetVHostMask().c_str());
		}
	}

public:
	HostServCore(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, PSEUDOCLIENT | VENDOR)
		, applied(this, "hostserv_vhost")
	{
		if (!IRCD || !IRCD->CanSetVHost)
			throw ModuleException("Your IRCd does not support vhosts");
	}

	void OnReload(Configuration::Conf &conf) override
	{
		const Warden::string &hsnick = conf.GetModule(this).Get<const Warden::string>("client");

		if (hsnick.empty())
			throw ConfigException(Module::name + ": <client> must be defined");

		BotInfo *bi = BotInfo::Find(hsnick, true);
		if (!bi)
			throw ConfigException(Module::name + ": no bot named " + hsnick);

		HostServ = bi;
	}

	void OnUserLogin(User *u) override
	{
		if (!IRCD->CanSetVHost)
			return;

		const NickAlias *na = NickAlias::Find(u->nick);
		if (!na || na->nc != u->Account() || !na->HasVHost())
			na = u->AccountNick();
		if (!na || !na->HasVHost())
			return;

		if (u->vhost.empty() || !u->vhost.equals_cs(na->GetVHostHost()) || (!na->GetVHostIdent().empty() && !u->GetVIdent().equals_cs(na->GetVHostIdent())))
		{
			// An oper who already has another vhost most likely got it from
			// their oper block; don't replace it, e.g. when everyone is logged
			// back in after a services restart (anope/anope#427). The HostServ
			// vhost comes back when they deoper (activate_on_deoper).
			if (u->HasMode("OPER") && !u->vhost.empty() && Config->GetModule(this).Get<bool>("keep_oper_vhost", "yes"))
				return;

			this->Apply(u, na);
		}
		else
			applied.Set(u, na->GetVHostHost()); // Already set, e.g. after a services restart.
	}

	void OnNickLogout(User *u) override
	{
		const auto *vhost = applied.Get(u);
		if (!vhost)
			return;

		const auto matches = u->vhost.equals_cs(*vhost);
		applied.Unset(u);
		if (!matches)
			return; // Something else changed it since; leave it alone.

		u->vhost.clear();
		IRCD->SendVHostDel(u);
		u->UpdateHost();
	}

	void OnNickDrop(CommandSource &source, NickAlias *na) override
	{
		if (na->HasVHost())
		{
			FOREACH_MOD(OnDeleteVHost, (na));
			na->RemoveVHost();
		}
	}

	void OnNickUpdate(User *u) override
	{
		this->OnUserLogin(u);
	}

	void OnUserModeUnset(const MessageSource &setter, User *u, const Warden::string &mname) override
	{
		if (mname != "OPER" || !Config->GetModule(this).Get<bool>("activate_on_deoper", "yes"))
			return;

		const NickAlias *na = u->Account() ? NickAlias::Find(u->nick) : nullptr;
		if (!na || na->nc != u->Account() || !na->HasVHost())
			na = u->AccountNick();

		if (na && na->HasVHost())
			this->OnUserLogin(u);
		else if (!u->vhost.empty() && IRCD->CanSetVHost)
		{
			// No HostServ vhost to go back to, so drop the oper vhost and
			// let the user's cloak (or real host) show again (anope/anope#462).
			IRCD->SendVHostDel(u);
			u->vhost.clear();
			u->UpdateHost();
		}
	}

	EventReturn OnPreHelp(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		if (!params.empty() || source.c || source.service != *HostServ)
			return EVENT_CONTINUE;
		source.Reply(_("%s commands:"), HostServ->nick.c_str());
		return EVENT_CONTINUE;
	}

	void OnSetVHost(NickAlias *na) override
	{
		if (Config->GetModule(this).Get<bool>("activate_on_set", "yes"))
		{
			User *u = User::Find(na->nick);

			if (u && u->Account() == na->nc)
				this->Apply(u, na);
		}
	}

	void OnDeleteVHost(NickAlias *na) override
	{
		if (Config->GetModule(this).Get<bool>("activate_on_set", "yes"))
		{
			User *u = User::Find(na->nick);

			if (u && u->Account() == na->nc)
			{
				IRCD->SendVHostDel(u);
				applied.Unset(u);
			}
		}
	}
};

MODULE_INIT(HostServCore)
