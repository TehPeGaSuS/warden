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

namespace
{
	// Shared argument parsing and paging for CHANLIST and USERLIST
	// (anope/anope#423): without a range only the first listmax entries are
	// shown, so a big network doesn't flood the oper off with SendQ.
	struct ListArgs final
	{
		Warden::string pattern;
		bool flag = false;
		unsigned from = 0, to = 0;

		bool Parse(CommandSource &source, const std::vector<Warden::string> &params, const char *flagname)
		{
			for (const auto &param : params)
			{
				if (param.equals_ci(flagname))
				{
					flag = true;
					continue;
				}

				auto dash = param.find('-');
				if (dash != Warden::string::npos && dash && isdigit(param[0]))
				{
					auto n1 = Warden::TryConvert<unsigned>(param.substr(0, dash));
					auto n2 = Warden::TryConvert<unsigned>(param.substr(dash + 1));
					if (!n1.has_value() || !n2.has_value() || !n1.value() || n1.value() > n2.value())
					{
						source.Reply(_("Incorrect range specified. The correct syntax is \037from\037-\037to\037."));
						return false;
					}
					from = n1.value();
					to = n2.value();
					continue;
				}

				if (pattern.empty())
					pattern = param;
			}
			return true;
		}
	};

	struct Pager final
	{
		unsigned from, to, cap;
		size_t matched = 0, shown = 0, shown_from = 0, shown_to = 0;

		Pager(const ListArgs &args, Module *owner)
			: from(args.from)
			, to(args.to)
			// An explicit range is the oper's own paging, so it isn't capped.
			, cap(args.from ? 0 : Config->GetModule(owner).Get<unsigned>("listmax", "50"))
		{
		}

		// Counts a matching entry and returns whether to show it.
		bool Want()
		{
			++matched;
			if (from && (matched < from || matched > to))
				return false;
			if (cap && shown >= cap)
				return false;
			if (!shown)
				shown_from = matched;
			shown_to = matched;
			++shown;
			return true;
		}
	};
}

class CommandOSChanList final
	: public Command
{
public:
	CommandOSChanList(Module *creator) : Command(creator, "operserv/chanlist", 0, 3)
	{
		this->SetDesc(_("List all channel records"));
		this->SetSyntax(_("[{\037pattern\037 | \037nick\037}] [\037SECRET\037] [\037from\037-\037to\037]"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		ListArgs args;
		if (!args.Parse(source, params, "SECRET"))
			return;
		const auto &pattern = args.pattern;
		User *u2;
		Pager pager(args, this->owner);

		if (!pattern.empty())
			Log(LOG_ADMIN, source, this) << "for " << pattern;
		else
			Log(LOG_ADMIN, source, this);

		// SECRET lists channels that are +s or +p.
		auto hidden = [&args](Channel *ch) { return !args.flag || ch->HasMode("SECRET") || ch->HasMode("PRIVATE"); };

		ListFormatter list(source.GetAccount());
		list.AddColumn(_("Name")).AddColumn(_("Users")).AddColumn(_("Modes")).AddColumn(_("Topic"));
		list.SetFlexible([](ListFormatter::ListEntry &row)
		{
			return row["Topic"].empty()
				? _("\002{name}\002 -- {users} user(s); +{modes}")
				: _("\002{name}\002 -- {users} user(s); +{modes} ({topic})");
		});


		if (!pattern.empty() && (u2 = User::Find(pattern, true)))
		{
			source.Reply(_("\002%s\002 channel list:"), u2->nick.c_str());

			for (const auto &[_, cc]: u2->chans)
			{
				if (!hidden(cc->chan) || !pager.Want())
					continue;

				ListFormatter::ListEntry entry;
				entry["Name"] = cc->chan->name;
				entry["Users"] = Warden::ToString(cc->chan->users.size());
				entry["Modes"] = cc->chan->GetModes(true, true);
				entry["Topic"] = cc->chan->topic;
				list.AddEntry(entry);
			}
		}
		else
		{
			// Sorted, so pages stay stable between calls.
			Warden::map<Channel *> ordered_map;
			for (const auto &[name, chan] : ChannelList)
				ordered_map[name] = chan;

			source.Reply(_("Channel list:"));

			for (const auto &[_, c] : ordered_map)
			{
				if (!pattern.empty() && !Warden::Match(c->name, pattern, false, true))
					continue;
				if (!hidden(c) || !pager.Want())
					continue;

				ListFormatter::ListEntry entry;
				entry["Name"] = c->name;
				entry["Users"] = Warden::ToString(c->users.size());
				entry["Modes"] = c->GetModes(true, true);
				entry["Topic"] = c->topic;
				list.AddEntry(entry);
			}
		}

		list.SendTo(source);
		if (pager.shown >= pager.matched)
			source.Reply(_("End of channel list. \002%zu\002 channels shown."), pager.shown);
		else if (!pager.shown)
			source.Reply(_("End of channel list - the range is past the last of the %zu channels."), pager.matched);
		else if (pager.shown_to >= pager.matched)
			source.Reply(_("End of channel list - %zu/%zu channels shown (%zu-%zu)."), pager.shown, pager.matched, pager.shown_from, pager.shown_to);
		else
			source.Reply(_("End of channel list - %zu/%zu channels shown (%zu-%zu). Give a range such as %zu-%zu to see more."), pager.shown, pager.matched, pager.shown_from, pager.shown_to, pager.shown_to + 1, pager.shown_to + pager.shown);
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Lists all channels currently in use on the IRC network, whether they "
			"are registered or not."
			"\n\n"
			"If \002pattern\002 is given, lists only channels that match it. If a nickname "
			"is given, lists only the channels the user using it is on. If SECRET is "
			"specified, lists only channels matching \002pattern\002 that have the +s or "
			"+p mode."
			"\n\n"
			"Long lists are cut short; give a range such as \00251-100\002 to see "
			"more."
		));

		const Warden::string &regexengine = Config->GetBlock("options").Get<const Warden::string>("regexengine");
		if (!regexengine.empty())
		{
			source.Reply(" ");
			source.Reply(_(
					"Regex matches are also supported using the %s engine. "
					"Enclose your pattern in // if this is desired."
				),
				regexengine.c_str());
		}

		return true;
	}
};

class CommandOSUserList final
	: public Command
{
public:
	CommandOSUserList(Module *creator) : Command(creator, "operserv/userlist", 0, 3)
	{
		this->SetDesc(_("List all user records"));
		this->SetSyntax(_("[{\037pattern\037 | \037channel\037}] [\037INVISIBLE\037] [\037from\037-\037to\037]"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		ListArgs args;
		if (!args.Parse(source, params, "INVISIBLE"))
			return;
		const auto &pattern = args.pattern;
		Channel *c;
		Pager pager(args, this->owner);

		if (!pattern.empty())
			Log(LOG_ADMIN, source, this) << "for " << pattern;
		else
			Log(LOG_ADMIN, source, this);

		ListFormatter list(source.GetAccount());
		list.AddColumn(_("Name")).AddColumn(_("Mask")).AddColumn(_("Realname"));
		list.SetFlexible(_("\002{name}\002 ({mask}) [{realname}]"));

		if (!pattern.empty() && (c = Channel::Find(pattern)))
		{
			source.Reply(_("\002%s\002 users list:"), pattern.c_str());

			for (const auto &[_, uc] : c->users)
			{
				if ((args.flag && !uc->user->HasMode("INVIS")) || !pager.Want())
					continue;

				ListFormatter::ListEntry entry;
				entry["Name"] = uc->user->nick;
				entry["Mask"] = uc->user->GetIdent() + "@" + uc->user->GetDisplayedHost();
				entry["Realname"] = uc->user->realname;
				list.AddEntry(entry);
			}
		}
		else
		{
			/* Historically this has been ordered, so... */
			Warden::map<User *> ordered_map;
			for (const auto &[nick, user] : UserListByNick)
				ordered_map[nick] = user;

			source.Reply(_("Users list:"));

			for (auto it = ordered_map.begin(); it != ordered_map.end(); ++it)
			{
				User *u2 = it->second;

				if (!pattern.empty())
				{
					/* check displayed host, host, and ip */
					Warden::string masks[] = {
						u2->nick + "!" + u2->GetIdent() + "@" + u2->GetDisplayedHost(),
						u2->nick + "!" + u2->GetIdent() + "@" + u2->host,
						u2->nick + "!" + u2->GetIdent() + "@" + u2->ip.addr()
					};

					bool match = false;
					for (const auto &mask : masks)
					{
						/* Check mask with realname included, too */
						if (Warden::Match(mask, pattern, false, true) || Warden::Match(mask + "#" + u2->realname, pattern, false, true))
						{
							match = true;
							break;
						}
					}

					if (!match)
						continue;
				}

				if ((args.flag && !u2->HasMode("INVIS")) || !pager.Want())
					continue;

				ListFormatter::ListEntry entry;
				entry["Name"] = u2->nick;
				entry["Mask"] = u2->GetIdent() + "@" + u2->GetDisplayedHost();
				entry["Realname"] = u2->realname;
				list.AddEntry(entry);
			}
		}

		list.SendTo(source);
		if (pager.shown >= pager.matched)
			source.Reply(_("End of users list. \002%zu\002 users shown."), pager.shown);
		else if (!pager.shown)
			source.Reply(_("End of users list - the range is past the last of the %zu users."), pager.matched);
		else if (pager.shown_to >= pager.matched)
			source.Reply(_("End of users list - %zu/%zu users shown (%zu-%zu)."), pager.shown, pager.matched, pager.shown_from, pager.shown_to);
		else
			source.Reply(_("End of users list - %zu/%zu users shown (%zu-%zu). Give a range such as %zu-%zu to see more."), pager.shown, pager.matched, pager.shown_from, pager.shown_to, pager.shown_to + 1, pager.shown_to + pager.shown);
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Lists all users currently online on the IRC network, whether their "
			"nick is registered or not."
			"\n\n"
			"If \002pattern\002 is given, lists only users that match it (it must be in "
			"the format nick!user@host[#realname]). If \002channel\002 is given, lists "
			"only users that are on the given channel. If INVISIBLE is specified, only users "
			"with the +i flag will be listed."
			"\n\n"
			"Long lists are cut short; give a range such as \00251-100\002 to see "
			"more."
		));

		const Warden::string &regexengine = Config->GetBlock("options").Get<const Warden::string>("regexengine");
		if (!regexengine.empty())
		{
			source.Reply(" ");
			source.Reply(_(
					"Regex matches are also supported using the %s engine. "
					"Enclose your pattern in // if this is desired."
				),
				regexengine.c_str());
		}

		return true;
	}
};

class OSList final
	: public Module
{
	CommandOSChanList commandoschanlist;
	CommandOSUserList commandosuserlist;

public:
	OSList(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, VENDOR),
		commandoschanlist(this), commandosuserlist(this)
	{

	}
};

MODULE_INIT(OSList)
