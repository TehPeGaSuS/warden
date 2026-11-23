// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2016-2022 Michael Hazell <michaelhazell@hotmail.com>
// Copyright (C) 2026 Warden Contributors
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// SPDX-License-Identifier: GPL-2.0-only

// Gives every account a default vhost made from its name, e.g.
// foo.users.example.net or user/foo. Based on Michael Hazell's (Techman)
// third-party hs_nethost and PeGaSuS's Anope 2.1 versions of it.

#include "module.h"

namespace
{
	Warden::string prefix, suffix, hashprefix;
	bool setifnone = false;

	// Marks vhosts this module set, so it never replaces one that was
	// requested or set by hand.
	const Warden::string CREATOR = "HostServ";

	// The account ID in base 36: short, and unique and stable per account.
	Warden::string Base36(uint64_t n)
	{
		static const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
		if (!n)
			return "0";

		Warden::string out;
		while (n)
		{
			out = Warden::string(1, digits[n % 36]) + out;
			n /= 36;
		}
		return out;
	}

	NickAlias *DisplayAlias(NickCore *nc)
	{
		for (auto *na : *nc->aliases)
			if (na->nick.equals_ci(nc->display))
				return na;
		return nullptr;
	}

	// Builds the vhost for na. Characters that can't go in a vhost are
	// dropped; when that happens the account ID is added so two nicks that
	// end up alike (foo|bar and foo[bar]) still get different vhosts.
	Warden::string BuildNetHost(NickAlias *na)
	{
		const auto &vhostchars = Config->GetBlock("networkinfo").Get<const Warden::string>("vhost_chars", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-/");

		Warden::string nick;
		auto changed = false;
		for (auto c : na->nick)
		{
			// '.' and '/' are allowed in vhosts but would split the nick.
			if (c == '.' || c == '/' || vhostchars.find(c) == Warden::string::npos)
				changed = true;
			else
				nick.push_back(c);
		}

		// A vhost can't start or end with '-'.
		const auto start = nick.find_first_not_of('-');
		if (start == Warden::string::npos)
			nick.clear();
		else if (start != 0 || nick[nick.length() - 1] == '-')
		{
			nick = nick.substr(start, nick.find_last_not_of('-') - start + 1);
			changed = true;
		}

		if (nick.empty())
		{
			nick = "user";
			changed = true;
		}

		// The ID goes before the suffix: foobar-1x2y.users.example.net,
		// or user/foobar/x-1x2y with prefix "user/" and hashprefix "/x-".
		if (changed)
			nick += hashprefix + Base36(na->nc->GetId());
		return prefix + nick + suffix;
	}

	// Sets na's net host. Unless forced, a vhost set by anything else is left
	// alone. Returns true if the vhost was set.
	bool SetNetHost(NickAlias *na, bool force = false)
	{
		if (na->HasVHost() && na->GetVHostCreator() != CREATOR && !force)
			return false;

		const auto vhost = BuildNetHost(na);
		if (!IRCD->IsHostValid(vhost))
		{
			Log(Config->GetClient("HostServ"), "nethost") << "Not setting vhost " << vhost << " on " << na->nick
				<< ": it is not a valid vhost. Check prefix, suffix and hashprefix against vhost_chars and allow_undotted_vhosts in the networkinfo block.";
			return false;
		}

		if (na->HasVHost() && na->GetVHostHost() == vhost && na->GetVHostIdent().empty())
			return false;

		na->SetVHost("", vhost, CREATOR);
		FOREACH_MOD(OnSetVHost, (na));
		return true;
	}
}

class CommandHSSetNetHosts final
	: public Command
{
public:
	CommandHSSetNetHosts(Module *creator)
		: Command(creator, "hostserv/setnethosts", 0, 1)
	{
		this->SetDesc(_("Give every account its default vhost"));
		this->SetSyntax("[ALL]");
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		const auto all = !params.empty() && params[0].equals_ci("ALL");
		size_t count = 0;
		for (const auto &[_, nc] : *NickCoreList)
		{
			// Opers usually have their own vhost; unconfirmed accounts get
			// theirs when they confirm.
			if (nc->o || nc->HasExt("UNCONFIRMED"))
				continue;

			auto *na = DisplayAlias(nc);
			if (na && SetNetHost(na, all))
				++count;
		}

		Log(LOG_ADMIN, source, this) << (all ? "ALL " : "") << "and set " << count << " vhost(s)";
		source.Reply(_("Set the default vhost on \002%zu\002 account(s)."), count);
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Gives every account its default vhost, made from its name. Accounts "
			"that already have a vhost set some other way (requested, or set by "
			"an operator) are skipped unless \002ALL\002 is given. Services "
			"operators and unconfirmed accounts are always skipped."
		));
		return true;
	}
};

class HSNetHost final
	: public Module
{
	CommandHSSetNetHosts commandhssetnethosts;

public:
	HSNetHost(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, VENDOR)
		, commandhssetnethosts(this)
	{
		if (!IRCD || !IRCD->CanSetVHost)
			throw ModuleException("Your IRCd does not support vhosts");
	}

	void Prioritize() override
	{
		// Run after ns_register etc. so the new account is complete.
		ModuleManager::SetPriority(this, PRIORITY_LAST);
	}

	void OnReload(Configuration::Conf &conf) override
	{
		const auto &block = conf.GetModule(this);
		prefix = block.Get<const Warden::string>("prefix");
		suffix = block.Get<const Warden::string>("suffix");
		hashprefix = block.Get<const Warden::string>("hashprefix", "-");
		setifnone = block.Get<bool>("setifnone");
	}

	void OnNickRegister(User *, NickAlias *na, const Warden::string &) override
	{
		// With confirmation on, the vhost is set when the account is confirmed.
		if (Config->GetModule("ns_register").Get<const Warden::string>("registration").equals_ci("none"))
			SetNetHost(na);
	}

	void OnNickConfirm(User *, NickCore *nc) override
	{
		if (auto *na = DisplayAlias(nc))
			SetNetHost(na);
	}

	void OnChangeCoreDisplay(NickCore *nc, const Warden::string &newdisplay) override
	{
		// The vhost follows the account name, but only if it was ours.
		auto *old = DisplayAlias(nc);
		if (old && old->HasVHost() && old->GetVHostCreator() == CREATOR)
		{
			old->RemoveVHost();
			FOREACH_MOD(OnDeleteVHost, (old));
		}

		for (auto *na : *nc->aliases)
		{
			if (na->nick.equals_ci(newdisplay))
			{
				SetNetHost(na);
				break;
			}
		}
	}

	void OnNickIdentify(User *u) override
	{
		// Optionally give older accounts that never had one their vhost too.
		if (!setifnone)
			return;

		auto *nc = u->Account();
		if (!nc || nc->o || nc->HasExt("UNCONFIRMED"))
			return;

		auto *na = DisplayAlias(nc);
		if (na && !na->HasVHost())
			SetNetHost(na);
	}

	void OnUserLogin(User *u) override
	{
		// SASL and other logins that skip IDENTIFY.
		OnNickIdentify(u);
	}
};

MODULE_INIT(HSNetHost)
