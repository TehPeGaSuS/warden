// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2016 Matt Schatz (genius3000) <genius3000@g3k.solutions>
// Copyright (C) 2026 Warden Contributors
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// SPDX-License-Identifier: GPL-2.0-only

// Lists the nicks and channels that will expire soon, following the same rules
// as the expiry itself. Based on genius3000's third-party os_expiring.

#include "module.h"

class CommandOSExpiring final
	: public Command
{
	struct Entry final
	{
		Warden::string name;
		time_t when;
		const char *note;
	};

	// When na will expire, or 0 if it won't.
	static time_t NickExpiry(NickAlias *na, time_t expire)
	{
		NickCore *nc = na->nc;
		if (na->HasExt("NS_NO_EXPIRE") || nc->HasExt("NS_SUSPENDED"))
			return 0;

		if (nc->HasExt("UNCONFIRMED"))
		{
			const auto unconfirmed = Config->GetModule("ns_register").Get<time_t>("unconfirmedexpire", "1d");
			return unconfirmed ? na->registered + unconfirmed : 0;
		}

		if (!expire)
			return 0;

		// Online and identified nicks are kept seen.
		auto *u = User::Find(na->nick, true);
		if (u && u->IsIdentified(true))
			return 0;

		if (nc->na == na && nc->aliases->size() > 1 && Config->GetModule("nickserv").Get<bool>("preservedisplay"))
			return 0;

		return na->last_seen + expire;
	}

	static time_t ChanExpiry(ChannelInfo *ci, time_t expire)
	{
		if (!expire || ci->HasExt("CS_NO_EXPIRE") || ci->HasExt("CS_SUSPENDED"))
			return 0;
		return ci->last_used + expire;
	}

	void Show(CommandSource &source, std::vector<Entry> &entries, const char *heading, const char *none, const Warden::string &range)
	{
		if (entries.empty())
		{
			source.Reply(none, range.c_str());
			return;
		}

		std::sort(entries.begin(), entries.end(), [](const auto &a, const auto &b) { return a.when < b.when; });
		const auto listmax = Config->GetModule(this->owner).Get<unsigned>("listmax", "50");

		ListFormatter list(source.GetAccount());
		list.AddColumn(_("Name")).AddColumn(_("Expires"));
		list.SetFlexible(_("\002{name}\002 expires {expires}"));
		for (size_t i = 0; i < entries.size() && i < listmax; ++i)
		{
			const auto &e = entries[i];
			ListFormatter::ListEntry le;
			le["Name"] = e.name;
			le["Expires"] = Warden::strftime(e.when, source.GetAccount(), true);
			if (e.note)
				le["Expires"] += Warden::string(" [") + source.Translate(e.note) + "]";
			list.AddEntry(le);
		}

		source.Reply(heading, range.c_str());
		list.SendTo(source);
		source.Reply(_("End of list - %zu/%zu shown, soonest first."), std::min<size_t>(entries.size(), listmax), entries.size());
	}

	void DoNicks(CommandSource &source, time_t range)
	{
		const auto expire = Config->GetModule("nickserv").Get<time_t>("expire", "1y");
		if (!range)
			range = expire ? expire / 4 : 7 * 86400;
		const auto until = Warden::CurTime + range;

		std::vector<Entry> entries;
		for (const auto &[_, na] : *NickAliasList)
		{
			const auto when = NickExpiry(na, expire);
			if (when && when <= until)
				entries.push_back({ na->nick, when, na->nc->HasExt("UNCONFIRMED") ? _("Unconfirmed") : nullptr });
		}

		Show(source, entries, _("Nicks expiring within %s:"), _("No nicks will expire within %s."), Warden::Duration(range, source.GetAccount()));
	}

	void DoChans(CommandSource &source, time_t range)
	{
		const auto expire = Config->GetModule("chanserv").Get<time_t>("expire", "30d");
		if (!range)
			range = expire ? expire / 4 : 7 * 86400;
		const auto until = Warden::CurTime + range;

		std::vector<Entry> entries;
		for (const auto &[_, ci] : *RegisteredChannelList)
		{
			const auto when = ChanExpiry(ci, expire);
			if (when && when <= until)
				entries.push_back({ ci->name, when, nullptr });
		}

		Show(source, entries, _("Channels expiring within %s:"), _("No channels will expire within %s."), Warden::Duration(range, source.GetAccount()));
	}

public:
	CommandOSExpiring(Module *creator)
		: Command(creator, "operserv/expiring", 0, 2)
	{
		this->SetDesc(_("List nicks and channels that will expire soon"));
		this->SetSyntax(_("[NICK | CHAN] [\037time\037]"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		auto nicks = true, chans = true;
		Warden::string when;
		for (const auto &param : params)
		{
			if (param.equals_ci("NICK"))
				chans = false;
			else if (param.equals_ci("CHAN"))
				nicks = false;
			else
				when = param;
		}
		if (!nicks && !chans)
		{
			this->OnSyntaxError(source, "");
			return;
		}

		time_t range = 0;
		if (!when.empty())
		{
			// A plain number is days.
			range = Warden::DoTime(when.is_pos_number_only() ? when + "d" : when);
			if (range <= 0)
			{
				source.Reply(_("\002%s\002 is not a valid time, e.g. \00230d\002 or \0022w\002."), when.c_str());
				return;
			}
		}

		if (Warden::NoExpire)
			source.Reply(_("Note: services are running with expiry turned off, so nothing will actually expire until that changes."));

		if (nicks)
			DoNicks(source, range);
		if (chans)
			DoChans(source, range);
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Lists the registered nicks and channels that will expire within "
			"\037time\037, soonest first, so you can see what is about to go. "
			"\002NICK\002 or \002CHAN\002 limits it to one of them."
			"\n\n"
			"\037time\037 is a duration such as \00230d\002, \0022w\002 or "
			"\0021d12h\002; a plain number means days. Without it, a quarter of "
			"the configured expiry time is used."
			"\n\n"
			"Nicks and channels that can't expire (NOEXPIRE, suspended, or a "
			"nick that is online and identified) are not listed."
		));
		return true;
	}
};

class OSExpiring final
	: public Module
{
	CommandOSExpiring commandosexpiring;

public:
	OSExpiring(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, VENDOR)
		, commandosexpiring(this)
	{
	}
};

MODULE_INIT(OSExpiring)
