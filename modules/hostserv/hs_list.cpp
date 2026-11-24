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

class CommandHSList final
	: public Command
{
public:
	CommandHSList(Module *creator) : Command(creator, "hostserv/list", 0, 2)
	{
		this->SetDesc(_("Display one or more vhost entries"));
		this->SetSyntax(_("[\037key\037] [\037from\037-\037to\037]"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		// LIST [key] [from-to]: a pattern, a range, or both (anope/anope#541).
		Warden::string key;
		int from = 0, to = 0;
		for (const auto &param : params)
		{
			const auto &range = param;
			auto dash = range.find('-');
			if (dash == Warden::string::npos || !dash || !isdigit(range[0]))
			{
				key = param;
				continue;
			}

			auto n1 = Warden::TryConvert<int>(range.substr(0, dash));
			auto n2 = Warden::TryConvert<int>(range.substr(dash + 1));
			if (!n1.has_value() || !n2.has_value() || n1.value() < 1 || n1.value() > n2.value())
			{
				source.Reply(_("Incorrect range specified. The correct syntax is \037from\037-\037to\037."));
				return;
			}
			from = n1.value();
			to = n2.value();
		}

		// Without a range only listmax entries are shown; a range is the
		// oper's own paging, so it isn't capped (anope/anope#498).
		const unsigned listmax = Config->GetModule(this->owner).Get<unsigned>("listmax", "50");
		const bool pattern = !key.empty();
		const unsigned cap = from ? 0 : listmax;
		unsigned matched = 0, shown = 0, shown_from = 0, shown_to = 0;

		ListFormatter list(source.GetAccount());
		list.AddColumn(_("Number")).AddColumn(_("Nick")).AddColumn(_("VHost")).AddColumn(_("Creator")).AddColumn(_("Created"));
		list.SetFlexible(_("{number}: \002{nick}\002 = {vhost} -- created by {creator} at {created}"));

		// Sorted by nick, so pages stay stable between calls.
		std::vector<NickAlias *> vhosts;
		for (const auto &[_, na] : *NickAliasList)
			if (na->HasVHost())
				vhosts.push_back(na);
		std::sort(vhosts.begin(), vhosts.end(), [](const NickAlias *a, const NickAlias *b) { return ci::less()(a->nick, b->nick); });

		for (auto *na : vhosts)
		{
			if (pattern && !Warden::Match(na->nick, key) && !Warden::Match(na->GetVHostHost(), key))
				continue;

			++matched;
			if (from && (matched < static_cast<unsigned>(from) || matched > static_cast<unsigned>(to)))
				continue;
			if (cap && shown >= cap)
				continue;

			if (!shown)
				shown_from = matched;
			shown_to = matched;
			++shown;

			ListFormatter::ListEntry entry;
			entry["Number"] = Warden::ToString(matched);
			entry["Nick"] = na->nick;
			entry["VHost"] = na->GetVHostMask();
			entry["Creator"] = na->GetVHostCreator();
			entry["Created"] = Warden::strftime(na->GetVHostCreated(), source.GetAccount(), true);
			list.AddEntry(entry);
		}

		if (!shown)
		{
			if (matched)
				source.Reply(_("The range is past the last of the %u vhosts."), matched);
			else
				source.Reply(_("No records to display."));
			return;
		}

		list.SendTo(source);

		if (shown >= matched)
			source.Reply(_("End of vhost list - %u vhosts shown."), shown);
		else if (shown_to >= matched)
			source.Reply(_("End of vhost list - %u/%u vhosts shown (%u-%u)."), shown, matched, shown_from, shown_to);
		else
			source.Reply(_("End of vhost list - %u/%u vhosts shown (%u-%u). Give a range such as \002%u-%u\002 to see more."), shown, matched, shown_from, shown_to, shown_to + 1, shown_to + shown);
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"This command lists registered vhosts to the operator. "
			"If a \037key\037 is specified, only entries whose nick or vhost match "
			"the pattern given in \037key\037 are displayed e.g. Rob* for all "
			"entries beginning with \"Rob\". "
			"If a \037from\037-\037to\037 range is given, only entries between "
			"\002from\002 and \002to\002 will be displayed, e.g. \0021-3\002 will display "
			"the first 3 nick/vhost entries. Both can be given together, e.g. "
			"\002Rob* 51-100\002. Without a range, long lists are cut short; the "
			"last line says how many vhosts there are and which range to ask "
			"for next."
		));
		return true;
	}
};

class HSList final
	: public Module
{
	CommandHSList commandhslist;

public:
	HSList(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, VENDOR),
		commandhslist(this)
	{
		if (!IRCD || !IRCD->CanSetVHost)
			throw ModuleException("Your IRCd does not support vhosts");
	}
};

MODULE_INIT(HSList)
