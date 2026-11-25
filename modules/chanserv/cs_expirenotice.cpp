// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2026 Warden Contributors
// Based on m_expirenotice by genius3000 (2016).
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// SPDX-License-Identifier: GPL-2.0-only

// Warns channel founders and successors by email and/or memo before their
// channels expire, and tells them when they have (anope/anope#412).

#include "module.h"
#include "modules/memoserv/service.h"

static Mail::Template expiring_email("chan_expiring");
static Mail::Template expired_email("chan_expired");

class CSExpireNotice final
	: public Module
{
	time_t warn = 0;
	bool mail = false, memo = false;

	// The last_seen/last_used value already warned about, so one warning is
	// sent per period of inactivity, even across restarts.
	SerializableExtensibleItem<time_t> warned;

	static bool AllAliasesIdle(const NickCore *nc, time_t idle)
	{
		for (const auto *na : *nc->aliases)
			if (Warden::CurTime - na->last_seen < idle)
				return false;
		return true;
	}

	// Sends a memo and/or an email. The email is skipped when MemoServ will
	// already mail the memo to the user (MEMO_MAIL, with memoserv:mail on).
	void Notify(NickCore *nc, const Mail::Template &tmpl, const Warden::map<Warden::string> &vars, const char *client, const Warden::string &memotext, bool memo_ok) const
	{
		bool memo_mailed = false;
		auto *bi = Config->GetClient(client);
		if (this->memo && memo_ok && MemoServ::service && bi)
		{
			if (MemoServ::service->Send(bi->nick, nc->display, memotext, true) == MemoServ::MEMO_SUCCESS)
				memo_mailed = nc->HasExt("MEMO_MAIL") && Config->GetModule("memoserv").Get<bool>("mail", "yes");
		}
		if (this->mail && !memo_mailed && !nc->email.empty())
			tmpl.Send(nc, vars);
	}

	void ReadSettings(Configuration::Conf &conf, time_t expire, const char *defwarn)
	{
		const auto &block = conf.GetModule(this);
		warn = expire ? block.Get<time_t>("warn", defwarn) : 0;
		if (expire && warn >= expire)
			warn = expire / 4;

		mail = memo = false;
		spacesepstream sep(block.Get<const Warden::string>("notify", "mail memo"));
		for (Warden::string method; sep.GetToken(method); )
		{
			if (method.equals_ci("mail"))
				mail = conf.GetBlock("mail").Get<bool>("usemail");
			else if (method.equals_ci("memo"))
				memo = true;
		}
	}

	bool Enabled() const { return warn && (mail || memo); }

	static std::vector<NickCore *> Owners(ChannelInfo *ci)
	{
		std::vector<NickCore *> owners;
		if (auto *founder = ci->GetFounder())
			owners.push_back(founder);
		auto *successor = ci->GetSuccessor();
		if (successor && successor != ci->GetFounder())
			owners.push_back(successor);
		return owners;
	}

	static time_t NickExpire()
	{
		return Config->GetModule("nickserv").Get<time_t>("expire", "1y");
	}

public:
	CSExpireNotice(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, VENDOR)
		, warned(this, "CS_EXPIRE_WARNED")
	{
	}

	void OnReload(Configuration::Conf &conf) override
	{
		ReadSettings(conf, conf.GetModule("chanserv").Get<time_t>("expire", "30d"), "3d");
		expiring_email.Reload(conf);
		expired_email.Reload(conf);
	}

	void OnPreChanExpire(ChannelInfo *ci, bool &expire) override
	{
		if (expire || !Enabled())
			return;
		if (ci->HasExt("CS_NO_EXPIRE") || ci->HasExt("CS_SUSPENDED"))
			return;

		const auto expire_at = ci->last_used + Config->GetModule("chanserv").Get<time_t>("expire", "30d");
		if (Warden::CurTime < expire_at - warn)
			return;

		const auto *last = warned.Get(ci);
		if (last && *last == ci->last_used)
			return;

		// Someone with access in the channel keeps it alive at expiry time.
		if (ci->c)
		{
			for (const auto &[_, uc] : ci->c->users)
			{
				auto ag = ci->AccessFor(uc->user, false);
				if (ag.founder || !ag.empty())
					return;
			}
		}
		warned.Set(ci, ci->last_used);

		Log(LOG_NORMAL, "chanserv/preexpire", Config->GetClient("ChanServ")) << "Warning about expiring channel " << ci->name << " (founder: " << (ci->GetFounder() ? ci->GetFounder()->display : "(none)") << "), expires " << Warden::strftime(expire_at);

		for (auto *nc : Owners(ci))
		{
			Warden::map<Warden::string> vars = {
				{ "account", nc->display },
				{ "channel", ci->name },
				{ "expires", Warden::strftime(expire_at, nc) },
				{ "network", Config->GetBlock("networkinfo").Get<const Warden::string>("networkname") },
			};
			auto memotext = Warden::Format(Language::Translate(nc, _("Your channel %s will expire on %s unless it is used.")), ci->name.c_str(), vars["expires"].c_str());
			Notify(nc, expiring_email, vars, "ChanServ", memotext, !AllAliasesIdle(nc, NickExpire()));
		}
	}

	void OnChanExpire(ChannelInfo *ci) override
	{
		if (!Enabled())
			return;

		for (auto *nc : Owners(ci))
		{
			Warden::map<Warden::string> vars = {
				{ "account", nc->display },
				{ "channel", ci->name },
				{ "network", Config->GetBlock("networkinfo").Get<const Warden::string>("networkname") },
			};
			auto memotext = Warden::Format(Language::Translate(nc, _("Your channel %s has expired.")), ci->name.c_str());
			Notify(nc, expired_email, vars, "ChanServ", memotext, !AllAliasesIdle(nc, NickExpire()));
		}
	}
};

MODULE_INIT(CSExpireNotice)
