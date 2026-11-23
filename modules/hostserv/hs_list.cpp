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
		this->SetSyntax(_("[\037key\037] [\037#X-Y\037]"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		// LIST [key] [#X-Y]: a pattern, a range, or both.
		Warden::string key, range;
		for (const auto &param : params)
		{
			if (param[0] == '#')
				range = param;
			else
				key = param;
		}
		int from = 0, to = 0;

		if (!range.empty())
		{
			const auto &key = range;
			size_t tmp = key.find('-');
			if (tmp == Warden::string::npos || tmp == key.length() || tmp == 1)
			{
				source.Reply(LIST_INCORRECT_RANGE);
				return;
			}
			for (unsigned i = 1, end = key.length(); i < end; ++i)
			{
				if (!isdigit(key[i]) && i != tmp)
				{
					source.Reply(LIST_INCORRECT_RANGE);
					return;
				}

				from = Warden::Convert<int>(key.substr(1, tmp - 1), 0);
				to = Warden::Convert<int>(key.substr(tmp + 1), 0);
			}
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
			entry["Created"] = Warden::strftime(na->GetVHostCreated(), NULL, true);
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
			source.Reply(_("End of vhost list - %u/%u vhosts shown (%u-%u). Give a range such as \002#%u-%u\002 to see more."), shown, matched, shown_from, shown_to, shown_to + 1, shown_to + shown);
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
			"If a \037#X-Y\037 style is used, only entries between the range of \002X\002 "
			"and \002Y\002 will be displayed, e.g. \002#1-3\002 will display the first 3 "
			"nick/vhost entries. Both can be given together, e.g. \002Rob* #51-100\002. Without a range, long lists are cut short; the "
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
