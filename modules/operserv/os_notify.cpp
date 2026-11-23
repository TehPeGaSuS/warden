// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2017-2019 Matt Schatz (genius3000) <genius3000@g3k.solutions>
// Copyright (C) 2026 Warden Contributors
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// SPDX-License-Identifier: GPL-2.0-only

// Lets operators watch users matching a mask (or joining matching channels):
// the events chosen with flags are logged under notify/user, notify/channel
// and notify/commands, usually to a log channel. Based on genius3000's
// third-party os_notify.

#include "module.h"

#define NOTIFY_TYPE "Notify"

/* Dataset for each Notify mask (entry) */
struct NotifyEntry final
	: Serializable
{
	Warden::string mask;	/* Mask to match */
	Warden::string reason;	/* Reason for this Notify */
	std::set<char> flags;	/* Flags of what to track */
	Warden::string creator;	/* Nick of creator */
	time_t created = 0;	/* Time of creation */
	time_t expires = 0;	/* Time of expiry */

	NotifyEntry()
		: Serializable(NOTIFY_TYPE)
	{
	}

	~NotifyEntry() override;
};

struct NotifyType final
	: Serialize::Type
{
	NotifyType()
		: Serialize::Type(NOTIFY_TYPE)
	{
	}

	void Serialize(Serializable *obj, Serialize::Data &data) const override
	{
		const auto *ne = static_cast<const NotifyEntry *>(obj);
		data.Store("mask", ne->mask);
		data.Store("reason", ne->reason);
		data.Store("flags", Warden::string(ne->flags.begin(), ne->flags.end()));
		data.Store("creator", ne->creator);
		data.Store("created", ne->created);
		data.Store("expires", ne->expires);
	}

	Serializable *Unserialize(Serializable *obj, Serialize::Data &data) const override;
};

/* Maps to track matched Notify Entries and Users */
typedef std::multimap<const NotifyEntry *, const User *> PerEntryMap;
typedef std::multimap<const User *, const NotifyEntry *> PerUserMap;

/* List of Notify Entries and currently Matched users */
class NotifyListStore final
{
protected:
	Serialize::Checker<std::vector<NotifyEntry *>> notifies;
	PerEntryMap match_entry;	/* Multiple Users mapped to one Notify Entry */
	PerUserMap match_user;		/* Multiple Notify Entires mapped to one User */

public:
	NotifyListStore()
		: notifies(NOTIFY_TYPE)
	{
	}

	~NotifyListStore()
	{
		for (auto i = notifies->size(); i > 0; --i)
			delete (*notifies).at(i - 1);

		match_entry.clear();
		match_user.clear();
	}

	void AddNotify(NotifyEntry *ne)
	{
		notifies->push_back(ne);
	}

	void DelNotify(NotifyEntry *ne)
	{
		/* Erase all Map items matching to this Notify Entry */
		match_entry.erase(ne);
		for (auto rit = match_user.rbegin(); rit != match_user.rend(); )
		{
			if (rit->second == ne)
				match_user.erase(--rit.base());
			else
				++rit;
		}

		/* Erase this Notify Entry from the Notify vector */
		auto it = std::find(notifies->begin(), notifies->end(), ne);
		if (it != notifies->end())
			notifies->erase(it);
	}

	void ClearNotifies()
	{
		for (auto i = notifies->size(); i > 0; --i)
			delete (*notifies).at(i - 1);

		match_entry.clear();
		match_user.clear();
	}

	void Expire(const NotifyEntry *ne)
	{
		Log(Config->GetClient("OperServ"), "expire/notify") << "Expiring notify entry " << ne->mask;
		delete ne;
	}

	const NotifyEntry *GetNotify(const unsigned number)
	{
		if (number >= notifies->size())
			return nullptr;

		const NotifyEntry *ne = notifies->at(number);
		if (ne->expires && ne->expires <= Warden::CurTime)
		{
			Expire(ne);
			return nullptr;
		}

		return ne;
	}

	const NotifyEntry *GetNotify(const Warden::string &mask)
	{
		for (auto i = notifies->size(); i > 0; --i)
		{
			const NotifyEntry *ne = notifies->at(i - 1);

			if (ne->expires && ne->expires <= Warden::CurTime)
				Expire(ne);
			else if (ne->mask.equals_ci(mask))
				return ne;
		}

		return nullptr;
	}

	/* Check if a User matches to a mask */
	static bool Check(const User *u, const Warden::string &mask)
	{
		/* Regex mask: Matches against u@h and n!u@h#r only */
		if (mask.length() >= 2 && mask[0] == '/' && mask[mask.length() - 1] == '/')
		{
			const Warden::string uh = u->GetIdent() + '@' + u->host;
			const Warden::string nuhr = u->nick + '!' + uh + '#' + u->realname;
			return (Warden::Match(uh, mask, false, true) || Warden::Match(nuhr, mask, false, true));
		}

		/* Use 'modes' Entry to perform matching per item (nick, user, host, real) */
		Entry notify_mask(mask, "", true);
		return notify_mask.Matches(const_cast<User *>(u), true);
	}

	/* Check if a Channel matches a mask */
	static bool Check(const Channel *c, const Warden::string &mask)
	{
		/* Regex mask */
		if (mask.length() >= 2 && mask[0] == '/' && mask[mask.length() - 1] == '/')
			return Warden::Match(c->name, mask, false, true);

		return mask.equals_ci(c->name);
	}

	const std::vector<NotifyEntry *> &GetNotifies()
	{
		for (auto i = notifies->size(); i > 0; --i)
		{
			const NotifyEntry *ne = notifies->at(i - 1);
			if (ne->expires && ne->expires <= Warden::CurTime)
				Expire(ne);
		}

		return *notifies;
	}

	size_t GetNotifiesCount() const
	{
		return notifies->size();
	}

	/* Check if a User is already mapped to a specific Notify Entry */
	bool ExistsAlready(const User *u, const NotifyEntry *ne) const
	{
		auto itpair = match_user.equal_range(u);
		for (auto it = itpair.first; it != itpair.second; ++it)
		{
			if (it->second == ne)
				return true;
		}

		return false;
	}

	/* Map a User as matched to a specific Notify Entry */
	void AddMatch(const User *u, const NotifyEntry *ne)
	{
		match_entry.emplace(ne, u);
		match_user.emplace(u, ne);
	}

	/* Remove a User from the matched Maps */
	void DelMatch(const User *u)
	{
		match_user.erase(u);
		for (auto it = match_entry.rbegin(); it != match_entry.rend(); )
		{
			if (it->second == u)
				match_entry.erase(--it.base());
			else
				++it;
		}
	}

	/* Check if a User is matched to any Notify Entries already */
	bool IsMatch(const User *u) const
	{
		return (match_user.count(u) > 0);
	}

	/* Check if a User is matched to a Notify Entry with a specific flag */
	bool HasFlag(const User *u, char flag) const
	{
		auto itpair = match_user.equal_range(u);
		for (auto it = itpair.first; it != itpair.second; ++it)
		{
			if (it->second->flags.count(flag) > 0)
				return true;
		}

		return false;
	}

	const PerEntryMap &GetEntryMap() const
	{
		return match_entry;
	}

	const PerUserMap &GetUserMap() const
	{
		return match_user;
	}
};

static NotifyListStore NotifyList;

NotifyEntry::~NotifyEntry()
{
	NotifyList.DelNotify(this);
}

Serializable *NotifyType::Unserialize(Serializable *obj, Serialize::Data &data) const
{
	NotifyEntry *ne;

	if (obj)
		ne = warden_dynamic_static_cast<NotifyEntry *>(obj);
	else
		ne = new NotifyEntry();

	ne->mask = data.Load("mask");
	ne->reason = data.Load("reason");
	ne->creator = data.Load("creator");
	ne->created = data.Load<time_t>("created");
	ne->expires = data.Load<time_t>("expires");

	const Warden::string flags = data.Load("flags");
	ne->flags.clear();
	for (auto f : flags)
		ne->flags.insert(f);

	if (!obj)
		NotifyList.AddNotify(ne);

	return ne;
}

/* Handle numbered (list) deletions */
class NotifyDelCallback final
	: public NumberList
{
	CommandSource &source;
	unsigned deleted = 0;
	Command *cmd;

public:
	NotifyDelCallback(CommandSource &_source, const Warden::string &numlist, Command *c)
		: NumberList(numlist, true)
		, source(_source)
		, cmd(c)
	{
	}

	~NotifyDelCallback() override
	{
		if (!deleted)
		{
			source.Reply(_("No matching entries on the notify list."));
			return;
		}

		if (Warden::ReadOnly)
			source.Reply(READ_ONLY_MODE);

		if (deleted == 1)
			source.Reply(_("Deleted 1 entry from the notify list."));
		else
			source.Reply(_("Deleted %u entries from the notify list."), deleted);
	}

	void HandleNumber(unsigned number) override
	{
		if (!number)
			return;

		const NotifyEntry *ne = NotifyList.GetNotify(number - 1);
		if (!ne)
			return;

		Log(LOG_ADMIN, source, cmd) << "to remove " << ne->mask << " from the list";
		delete ne;
		++deleted;
	}
};

class CommandOSNotify final
	: public Command
{
private:
	void DoAdd(CommandSource &source, const std::vector<Warden::string> &params)
	{
		Warden::string expiry, str_flags, mask, reason;

		// ADD [+expiry] flags|* mask [:]reason, e.g.
		//   ADD +30d cdjp idiot!moron@somewhere.com Annoying spammer
		//   ADD * helper!help@*.isp.com#Here to help :Impersonating staff
		Warden::string rest;
		for (size_t i = 1; i < params.size(); ++i)
			rest += (i > 1 ? " " : "") + params[i];
		spacesepstream args(rest);
		Warden::string first;
		args.GetToken(first);
		if (!first.empty() && first[0] == '+')
		{
			expiry = first.substr(1);
			args.GetToken(str_flags);
		}
		else
		{
			expiry = Config->GetModule(this->owner).Get<const Warden::string>("expiry", "30d");
			str_flags = first;
		}

		const auto masktext = args.GetRemaining();
		if (str_flags.empty() || masktext.empty())
		{
			this->OnSyntaxError(source, "ADD");
			return;
		}

		// Like AKILL, a plain number is days, and 0 means it never expires.
		time_t expires = Warden::DoTime(expiry.is_pos_number_only() ? expiry + "d" : expiry);
		if (expires < 0)
		{
			source.Reply(BAD_EXPIRY_TIME);
			return;
		}
		if (expires > 0)
			expires += Warden::CurTime;

		/* Acceptable flags are:
		 * c = Connects
		 * d = Disconnects
		 * i = channel Invites
		 * j = channel Joins
		 * k = channel Kicks
		 * m = channel Modes
		 * n = Nick changes
		 * p = channel Parts
		 * s = Services commands (-SET)
		 * S = Services SET commands
		 * t = Topics
		 * u = Usermodes
		 */
		const Warden::string all_flags = "Scdijkmnpstu";

		if (str_flags == "*")
		{
			str_flags = all_flags;
		}
		else if (str_flags.find_first_not_of(all_flags) != Warden::string::npos)
		{
			source.Reply(_("Incorrect flags character(s) given."));
			return;
		}

		std::set<char> flags;
		for (auto f : str_flags)
			flags.insert(f);

		spacesepstream sep(masktext);
		sep.GetToken(mask);

		if (sep.StreamEnd())
		{
			this->OnSyntaxError(source, "ADD");
			return;
		}

		size_t pound = mask.find('#');
		size_t at = mask.find('@');

		/* If '#' is after '@', we've got a real name */
		if ((pound != Warden::string::npos && at != Warden::string::npos) && pound > at)
		{
			const Warden::string remaining = sep.GetRemaining();

			size_t co = remaining[0] == ':' ? 0 : remaining.rfind(" :");
			if (co == Warden::string::npos)
			{
				this->OnSyntaxError(source, "ADD");
				return;
			}

			if (co != 0)
				++co;

			reason = remaining.substr(co + 1);
			mask += " " + remaining.substr(0, co);
			mask.trim();
		}
		else
		{
			reason = sep.GetRemaining();
			if (!reason.empty() && reason[0] == ':')
				reason.erase(0, 1);
		}

		if (mask.length() >= 2 && mask[0] == '/' && mask[mask.length() - 1] == '/')
		{
			const Warden::string &regexengine = Config->GetBlock("options").Get<const Warden::string>("regexengine");

			if (regexengine.empty())
			{
				source.Reply(_("Regex is disabled."));
				return;
			}

			ServiceReference<RegexProvider> provider("Regex", regexengine);
			if (!provider)
			{
				source.Reply(_("Unable to find regex engine %s."), regexengine.c_str());
				return;
			}

			try
			{
				Warden::string stripped_mask = mask.substr(1, mask.length() - 2);
				delete provider->Compile(stripped_mask);
			}
			catch (const RegexException &ex)
			{
				source.Reply("%s", ex.GetReason().c_str());
				return;
			}
		}

		if (mask.find_first_not_of("/~@.*?#") == Warden::string::npos)
		{
			source.Reply(USERHOST_MASK_TOO_WIDE, mask.c_str());
			return;
		}

		/* Valid masks either include a '@' or have '#' first (non-regex)
		 * Regex chan matches just require '#' in the mask
		 */
		if ((mask.find('@') == Warden::string::npos) &&
			(mask[0] != '#') &&
			(mask.length() < 2 || mask[0] != '/' || mask.find('#') == Warden::string::npos))
		{
			source.Reply(_("Mask must be at least \037user\037@\037host\037 or have a \037#\037 for channel masks."));
			return;
		}

		NotifyEntry *ne = const_cast<NotifyEntry *>(NotifyList.GetNotify(mask));
		bool created = true;
		if (ne)
		{
			created = false;
			delete ne;
		}
		ne = new NotifyEntry();

		ne->mask = mask;
		ne->reason = reason;
		ne->flags = flags;
		ne->creator = source.GetNick();
		ne->created = Warden::CurTime;
		ne->expires = expires;
		NotifyList.AddNotify(ne);

		if (Warden::ReadOnly)
			source.Reply(READ_ONLY_MODE);

		unsigned matches = 0;

		/* If mask contains '#' but not '@', it's a channel mask */
		if (pound != Warden::string::npos && at == Warden::string::npos)
		{
			for (const auto &[_, c] : ChannelList)
			{
				if (!NotifyList.Check(c, ne->mask))
					continue;

				for (const auto &[u, _2] : c->users)
				{
					if (NotifyList.ExistsAlready(u, ne))
						continue;

					NotifyList.AddMatch(u, ne);
					matches++;
				}
			}
		}
		else
		{
			for (const auto &[_, u] : UserListByNick)
			{
				if (NotifyList.Check(u, ne->mask))
				{
					NotifyList.AddMatch(u, ne);
					matches++;
				}
			}
		}

		Log(LOG_ADMIN, source, this) << "to " << (created ? "add" : "modify") << " a notify on " << mask << " for reason: " << reason << " (matches: " << matches << " user(s))";
		if (created)
			source.Reply(_("Added a notify on \002%s\002, matching %u user(s)."), mask.c_str(), matches);
		else
			source.Reply(_("Changed the notify on \002%s\002, matching %u user(s)."), mask.c_str(), matches);
	}

	void DoDel(CommandSource &source, const std::vector<Warden::string> &params)
	{
		const Warden::string &match = params.size() > 1 ? params[1] : "";

		if (match.empty())
		{
			this->OnSyntaxError(source, "DEL");
			return;
		}

		if (NotifyList.GetNotifiesCount() == 0)
		{
			source.Reply(_("The notify list is empty."));
			return;
		}

		if (isdigit(match[0]) && match.find_first_not_of("1234567890,-") == Warden::string::npos)
		{
			NotifyDelCallback list(source, match, this);
			list.Process();
		}
		else
		{
			const NotifyEntry *ne = NotifyList.GetNotify(match);
			if (!ne)
			{
				source.Reply(_("\002%s\002 not found on the notify list."), match.c_str());
				return;
			}

			if (Warden::ReadOnly)
				source.Reply(READ_ONLY_MODE);

			Log(LOG_ADMIN, source, this) << "to remove " << ne->mask << " from the list";
			source.Reply(_("\002%s\002 deleted from the notify list."), ne->mask.c_str());
			delete ne;
		}
	}

	static void AddListEntry(CommandSource &source, ListFormatter &list, const NotifyEntry *ne, unsigned number)
	{
		ListFormatter::ListEntry entry;
		entry["Number"] = Warden::ToString(number);
		entry["Mask"] = ne->mask;
		entry["Flags"] = Warden::string(ne->flags.begin(), ne->flags.end());
		entry["Reason"] = ne->reason;
		entry["Created"] = Warden::strftime(ne->created, source.GetAccount(), true);
		entry["By"] = ne->creator;
		entry["Expires"] = Warden::Expires(ne->expires, source.GetAccount());
		list.AddEntry(entry);
	}

	void ProcessList(CommandSource &source, const std::vector<Warden::string> &params, ListFormatter &list)
	{
		const Warden::string &match = params.size() > 1 ? params[1] : "";

		if (!match.empty() && isdigit(match[0]) && match.find_first_not_of("1234567890,-") == Warden::string::npos)
		{
			class ListCallback final
				: public NumberList
			{
				CommandSource &source;
				ListFormatter &list;

			public:
				ListCallback(CommandSource &_source, ListFormatter &_list, const Warden::string &numstr)
					: NumberList(numstr, false)
					, source(_source)
					, list(_list)
				{
				}

				void HandleNumber(unsigned number) override
				{
					if (!number)
						return;

					const NotifyEntry *ne = NotifyList.GetNotify(number - 1);
					if (!ne)
						return;

					AddListEntry(source, list, ne, number);
				}
			}
			nl_list(source, list, match);
			nl_list.Process();
		}
		else
		{
			const std::vector<NotifyEntry *> &notifies = NotifyList.GetNotifies();
			for (unsigned i = 0; i < notifies.size(); ++i)
			{
				const NotifyEntry *ne = notifies.at(i);
				if (!ne)
					continue;

				if (match.empty() || match.equals_ci(ne->mask) || Warden::Match(ne->mask, match, false, true))
					AddListEntry(source, list, ne, i + 1);
			}
		}

		if (list.IsEmpty())
			source.Reply(_("No matching entries on the notify list."));
		else
		{
			source.Reply(_("Current notify list:"));
			list.SendTo(source);
			source.Reply(_("End of notify list."));
		}
	}

	void DoList(CommandSource &source, const std::vector<Warden::string> &params)
	{
		if (NotifyList.GetNotifiesCount() == 0)
		{
			source.Reply(_("The notify list is empty."));
			return;
		}

		ListFormatter list(source.GetAccount());
		list.AddColumn(_("Number")).AddColumn(_("Mask")).AddColumn(_("Reason"));

		this->ProcessList(source, params, list);
	}

	void DoView(CommandSource &source, const std::vector<Warden::string> &params)
	{
		if (NotifyList.GetNotifiesCount() == 0)
		{
			source.Reply(_("The notify list is empty."));
			return;
		}

		ListFormatter list(source.GetAccount());
		list.AddColumn(_("Number")).AddColumn(_("Mask")).AddColumn(_("Flags")).AddColumn(_("Reason"));
		list.AddColumn(_("Created")).AddColumn(_("By")).AddColumn(_("Expires"));

		this->ProcessList(source, params, list);
	}

	void DoClear(CommandSource &source, const std::vector<Warden::string> &params)
	{
		if (NotifyList.GetNotifiesCount() == 0)
		{
			source.Reply(_("The notify list is empty."));
			return;
		}

		if (Warden::ReadOnly)
			source.Reply(READ_ONLY_MODE);

		NotifyList.ClearNotifies();
		Log(LOG_ADMIN, source, this) << "to clear the list";
		source.Reply(_("The notify list has been cleared."));
	}

	void DoShow(CommandSource &source, const std::vector<Warden::string> &params)
	{
		const PerEntryMap &current = NotifyList.GetEntryMap();
		if (current.empty())
		{
			source.Reply(_("No matching Users are currently online."));
			return;
		}

		ListFormatter list(source.GetAccount());
		list.AddColumn(_("Flags/Nick")).AddColumn(_("Mask")).AddColumn(_("Reason/Online Since"));

		Warden::string last_mask;
		for (const auto &[ne, u] : current)
		{
			if (!ne || !u)
				continue;

			if (last_mask != ne->mask)
			{
				ListFormatter::ListEntry entry;
				entry["Flags/Nick"] = Warden::string(ne->flags.begin(), ne->flags.end());
				entry["Mask"] = ne->mask;
				entry["Reason/Online Since"] = ne->reason;
				list.AddEntry(entry);

				last_mask = ne->mask;
			}

			ListFormatter::ListEntry subentry;
			subentry["Flags/Nick"] = u->nick;
			subentry["Mask"] = u->GetIdent() + "@" + u->host + "#" + u->realname;
			subentry["Reason/Online Since"] = Warden::strftime(u->signon, source.GetAccount(), true);
			list.AddEntry(subentry);
		}

		if (list.IsEmpty())
			source.Reply(_("No matching entries currently online."));
		else
		{
			source.Reply(_("Currently matched online users:"));
			list.SendTo(source);
			source.Reply(_("End of matched online users."));
		}
	}

	void DoRemove(CommandSource &source, const std::vector<Warden::string> &params)
	{
		if (NotifyList.GetNotifiesCount() == 0)
		{
			source.Reply(_("The notify list is empty."));
			return;
		}

		if (params.size() != 2)
		{
			this->OnSyntaxError(source, "REMOVE");
			return;
		}

		const PerUserMap &current = NotifyList.GetUserMap();
		if (current.empty())
		{
			source.Reply(_("No matching Users are currently online."));
			return;
		}

		const User *u = User::Find(params[1], true);
		if (!u)
		{
			source.Reply(_("No user found by the nick of %s."), params[1].c_str());
			return;
		}

		if (!NotifyList.IsMatch(u))
		{
			source.Reply(_("%s is not currently a matched User."), u->nick.c_str());
			return;
		}

		NotifyList.DelMatch(u);
		Log(LOG_ADMIN, source, this) << "to remove " << u->nick << " from the matched Users list for Notify";
		source.Reply(_("%s has been removed from the matched Users list."), u->nick.c_str());
	}

public:
	CommandOSNotify(Module *creator)
		: Command(creator, "operserv/notify", 1, 4)
	{
		this->SetDesc(_("Watch what users matching a mask do"));
		this->SetSyntax(_("ADD [+\037expiry\037] \037flags\037 \037mask\037 [:]\037reason\037"));
		this->SetSyntax(_("DEL {\037mask\037 | \037entry-num\037 | \037list\037}"));
		this->SetSyntax(_("LIST [\037mask\037 | \037entry-num\037 | \037list\037]"));
		this->SetSyntax(_("VIEW [\037mask\037 | \037entry-num\037 | \037list\037]"));
		this->SetSyntax("CLEAR");
		this->SetSyntax("SHOW");
		this->SetSyntax(_("REMOVE \037nick\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		const Warden::string &subcmd = params[0];

		if (subcmd.equals_ci("ADD"))
			this->DoAdd(source, params);
		else if (subcmd.equals_ci("DEL"))
			this->DoDel(source, params);
		else if (subcmd.equals_ci("LIST"))
			this->DoList(source, params);
		else if (subcmd.equals_ci("VIEW"))
			this->DoView(source, params);
		else if (subcmd.equals_ci("CLEAR"))
			this->DoClear(source, params);
		else if (subcmd.equals_ci("SHOW"))
			this->DoShow(source, params);
		else if (subcmd.equals_ci("REMOVE"))
			this->DoRemove(source, params);
		else
			this->OnSyntaxError(source, "");
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
				"Watches users who match a mask: what they do is logged (under "
				"notify/user, notify/channel and notify/commands, usually to a log "
				"channel) for operators to follow."
				"\n\n"
				"\002ADD\002 adds a mask. It can be \037nick!user@host#realname\037 "
				"(at least \037user@host\037), or a \037#channel\037 to watch everyone "
				"who joins a matching channel. If the mask has a realname, put a \002:\002 "
				"before the reason. \037expiry\037 is like \0027d\002 or \0021h30m\002 "
				"(a plain number is days, \002+0\002 never expires); without it the "
				"default of %s is used."
				"\n\n"
				"\037flags\037 choose what is logged, or \002*\002 for everything:\n"
				"  c - connects       d - disconnects     n - nick changes\n"
				"  u - user modes     j - channel joins   p - channel parts\n"
				"  k - kicks          m - channel modes   t - topic changes\n"
				"  i - invites        s - services commands   S - services SET commands"
				"\n\n"
				"\002DEL\002 removes entries by mask, number or list (e.g. \0021-3,5\002). "
				"\002LIST\002 and \002VIEW\002 show them, \002VIEW\002 in more detail. "
				"\002CLEAR\002 removes all of them. \002SHOW\002 lists the masks that "
				"match someone online, with those users. \002REMOVE\002 stops watching "
				"one online user until they match again (e.g. after a silly nick change)."
				"\n\n"
				"Commands that take passwords or codes are logged without their parameters."
			),
			Config->GetModule(this->owner).Get<const Warden::string>("expiry", "30d").c_str());

		const auto &regexengine = Config->GetBlock("options").Get<const Warden::string>("regexengine");
		if (!regexengine.empty())
		{
			source.Reply(" ");
			source.Reply(_(
					"Regex matches are also supported using the %s engine. For user "
					"masks they are matched against \037user@host\037 and "
					"\037nick!user@host#realname\037. Enclose your pattern in // if "
					"this is desired."
				),
				regexengine.c_str());
		}
		return true;
	}
};

class OSNotify final
	: public Module
{
	NotifyType notifyentry_type;
	CommandOSNotify commandosnotify;
	BotInfo *OperServ = nullptr;

	static Warden::string BuildNUHR(const User *u)
	{
		if (!u)
			return "unknown";

		return Warden::string(u->nick + "!" + u->GetIdent() + "@" + u->host + "#" + u->realname);
	}

	void NLog(const Warden::string &t, const char *m, ...) ATTR_FORMAT(3, 4)
	{
		char buf[4096];

		va_list args;
		va_start(args, m);
		vsnprintf(buf, sizeof(buf), m, args);
		va_end(args);

		Log(LOG_NORMAL, "notify/" + t, OperServ) << "NOTIFY: " << buf;
	}

	void Init()
	{
		const std::vector<NotifyEntry *> &notifies = NotifyList.GetNotifies();
		if (notifies.empty())
			return;

		unsigned matches = 0;
		for (const auto &[_, u] : UserListByNick)
		{
			if (!u || (u->server && u->server->IsULined()))
				continue;

			bool matched = false;
			for (auto i = notifies.size(); i > 0; --i)
			{
				const NotifyEntry *ne = notifies.at(i - 1);
				if (!ne)
					continue;

				if (NotifyList.Check(u, ne->mask) && !NotifyList.ExistsAlready(u, ne))
				{
					NotifyList.AddMatch(u, ne);
					matched = true;
				}
			}

			if (matched)
				matches++;
		}

		if (matches > 0)
			NLog("user", "Matched %u user(s) against the Notify list", matches);
	}

	unsigned CheckUserOrChannel(User *u, Channel *c = nullptr, bool wantChan = false)
	{
		const std::vector<NotifyEntry *> &notifies = NotifyList.GetNotifies();
		if (!u || (wantChan && !c) || notifies.empty() || (u->server && u->server->IsULined()))
			return 0;

		unsigned matches = 0;
		for (auto i = notifies.size(); i > 0; --i)
		{
			const NotifyEntry *ne = notifies.at(i - 1);
			if (!ne)
				continue;

			bool matched = false;
			if (wantChan && c)
				matched = NotifyList.Check(c, ne->mask);
			else if (!wantChan)
				matched = NotifyList.Check(u, ne->mask);

			if (matched)
			{
				if (NotifyList.ExistsAlready(u, ne))
					continue;

				NotifyList.AddMatch(u, ne);
				matches++;
			}
		}

		return matches;
	}

public:
	OSNotify(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, VENDOR)
		, commandosnotify(this)
	{
		if (Me && Me->IsSynced())
			this->Init();
	}

	void OnReload(Configuration::Conf &conf) override
	{
		OperServ = conf.GetClient("OperServ");
	}

	void OnUplinkSync(Server *) override
	{
		this->Init();
	}

	void OnUserConnect(User *u, bool &) override
	{
		if (Me && !Me->IsSynced())
			return;

		unsigned matches = CheckUserOrChannel(u);
		if (matches > 0)
		{
			if (NotifyList.HasFlag(u, 'c'))
				NLog("user", "'%s' connected [matches %u Notify mask(s)]", BuildNUHR(u).c_str(), matches);
		}
	}

	void OnUserQuit(User *u, const Warden::string &msg) override
	{
		if (NotifyList.IsMatch(u))
		{
			if (NotifyList.HasFlag(u, 'd'))
				NLog("user", "'%s' disconnected (reason: %s)", BuildNUHR(u).c_str(), msg.c_str());

			NotifyList.DelMatch(u);
		}
	}

	void OnUserNickChange(User *u, const Warden::string &oldnick) override
	{
		const Warden::string nuhr = oldnick + "!" + u->GetIdent() + "@" + u->host + "#" + u->realname;
		bool oldmatch = NotifyList.IsMatch(u);

		unsigned matches = CheckUserOrChannel(u);

		if (!NotifyList.HasFlag(u, 'n'))
			return;

		if (matches > 0)
		{
			if (oldmatch)
				NLog("user", "'%s' changed nick to %s [matches an additional %u Notify mask(s)]", nuhr.c_str(), u->nick.c_str(), matches);
			else
				NLog("user", "'%s' changed nick to %s [matches %u Notify mask(s)]", nuhr.c_str(), u->nick.c_str(), matches);
		}
		else if (oldmatch)
			NLog("user", "'%s' changed nick to %s", nuhr.c_str(), u->nick.c_str());
	}

	void OnJoinChannel(User *u, Channel *c) override
	{
		bool oldmatch = NotifyList.IsMatch(u);

		unsigned matches = CheckUserOrChannel(u, c, true);

		if (!NotifyList.HasFlag(u, 'j'))
			return;

		if (matches > 0)
		{
			if (oldmatch)
				NLog("channel", "'%s' joined %s [matches an additional %u Notify mask(s)]", BuildNUHR(u).c_str(), c->name.c_str(), matches);
			else
				NLog("channel", "'%s' joined %s [matches %u Notify mask(s)]", BuildNUHR(u).c_str(), c->name.c_str(), matches);
		}
		else if (oldmatch)
			NLog("channel", "'%s' joined %s", BuildNUHR(u).c_str(), c->name.c_str());
	}

	void OnPartChannel(User *u, Channel *c, const Warden::string &channel, const Warden::string &msg) override
	{
		if (NotifyList.HasFlag(u, 'p'))
			NLog("channel", "'%s' parted %s (reason: %s)", BuildNUHR(u).c_str(), c->name.c_str(), msg.c_str());
	}

	void OnUserKicked(const MessageSource &source, User *target, const Warden::string &channel, ChannelStatus &status, const Warden::string &kickmsg) override
	{
		User *u = source.GetUser();

		if (NotifyList.HasFlag(target, 'k'))
			NLog("channel", "'%s' was kicked from %s by %s (reason: %s)", BuildNUHR(target).c_str(), channel.c_str(), (u ? u->nick.c_str() : "unknown"), kickmsg.c_str());

		if (u && NotifyList.HasFlag(u, 'k'))
			NLog("channel", "'%s' kicked %s from %s (reason: %s)", BuildNUHR(u).c_str(), target->nick.c_str(), channel.c_str(), kickmsg.c_str());
	}

	void OnUserMode(const MessageSource &setter, User *u, const Warden::string &mname, bool setting)
	{
		const Warden::string nuhr = BuildNUHR(u);
		UserMode *um = ModeManager::FindUserModeByName(mname);

		if (setter.GetUser() && setter.GetUser() != u)
			NLog("user", "%s %sset mode %c (%s) on '%s'", setter.GetUser()->nick.c_str(), (setting ? "" : "un"), (um ? um->mchar : '\0'), mname.c_str(), nuhr.c_str());
		else
			NLog("user", "'%s' %sset mode %c (%s)", nuhr.c_str(), (setting ? "" : "un"), (um ? um->mchar : '\0'), mname.c_str());
	}

	void OnUserModeSet(const MessageSource &setter, User *u, const Warden::string &mname) override
	{
		if (NotifyList.HasFlag(u, 'u'))
			OnUserMode(setter, u, mname, true);
	}

	void OnUserModeUnset(const MessageSource &setter, User *u, const Warden::string &mname) override
	{
		if (NotifyList.HasFlag(u, 'u'))
			OnUserMode(setter, u, mname, false);
	}

	void OnChannelMode(Channel *c, MessageSource &setter, ChannelMode *mode, const Warden::string &param, bool setting)
	{
		const User *u = setter.GetUser();
		if (!u)
			return;

		if (NotifyList.HasFlag(u, 'm'))
		{
			if (mode->type == MODE_STATUS)
			{
				const User *target = User::Find(param, false);
				NLog("channel", "'%s' %sset channel mode %c (%s) on %s on %s", BuildNUHR(u).c_str(), (setting ? "" : "un"), mode->mchar, mode->name.c_str(), (target ? target->nick.c_str() : "unknown"), c->name.c_str());
			}
			else
				NLog("channel", "'%s' %sset channel mode %c (%s) [%s] on %s", BuildNUHR(u).c_str(), (setting ? "" : "un"), mode->mchar, mode->name.c_str(), param.c_str(), c->name.c_str());
		}
		else if (mode->type == MODE_STATUS)
		{
			const User *target = User::Find(param, false);
			if (target && NotifyList.HasFlag(target, 'm'))
				NLog("channel", "%s %sset channel mode %c (%s) on '%s' on %s", u->nick.c_str(), (setting ? "" : "un"), mode->mchar, mode->name.c_str(), BuildNUHR(target).c_str(), c->name.c_str());
		}
	}

	EventReturn OnChannelModeSet(Channel *c, MessageSource &setter, ChannelMode *mode, const ModeData &data) override
	{
		OnChannelMode(c, setter, mode, data.value, true);

		return EVENT_CONTINUE;
	}

	EventReturn OnChannelModeUnset(Channel *c, MessageSource &setter, ChannelMode *mode, const Warden::string &param) override
	{
		OnChannelMode(c, setter, mode, param, false);

		return EVENT_CONTINUE;
	}

	void OnTopicUpdated(User *source, Channel *c, const Warden::string &user, const Warden::string &topic) override
	{
		/* Ignore Services setting topic upon channel creation */
		if (c->topic_ts != Warden::CurTime && c->topic_ts != c->topic_time)
			return;

		const User *u = source ? source : User::Find(user, false);

		if (u && NotifyList.HasFlag(u, 't'))
			NLog("channel", "'%s' changed topic on %s to %s", BuildNUHR(u).c_str(), c->name.c_str(), topic.c_str());
	}

	void UserInvite(const Warden::string &source, const Warden::string &target, const Warden::string &chan)
	{
		User *src = User::Find(source, false);
		User *dst = User::Find(target, false);

		if (src && NotifyList.HasFlag(src, 'i'))
			NLog("channel", "'%s' invited %s to %s", BuildNUHR(src).c_str(), (dst ? dst->nick.c_str() : target.c_str()), chan.c_str());
		else if (dst && NotifyList.HasFlag(dst, 'i'))
			NLog("channel", "%s invited '%s' to %s", (src ? src->nick.c_str() : source.c_str()), BuildNUHR(dst).c_str(), chan.c_str());
	}

	void OnPostCommand(CommandSource &source, Command *command, const std::vector<Warden::string> &params) override
	{
		const User *u = source.GetUser();
		if (!u)
			return;

		const Warden::string &cmd = command->name;
		if (cmd == "chanserv/invite" && !params.empty())
			UserInvite(source.GetNick(), (params.size() > 1 ? params[1] : source.GetNick()), params[0]);

		if ((!NotifyList.HasFlag(u, 's') && !Warden::Match(cmd, "*/set/*")) ||
		    (!NotifyList.HasFlag(u, 'S') && Warden::Match(cmd, "*/set/*")))
			return;

		// Commands that take passwords, confirmation codes or private
		// text are logged without their parameters.
		static const std::set<Warden::string> hidden = {
			"nickserv/register", "nickserv/identify", "nickserv/login", "nickserv/confirm",
			"nickserv/group", "nickserv/recover", "nickserv/resetpass", "nickserv/drop",
			"nickserv/set/password", "nickserv/saset/password", "nickserv/cert",
			"chanserv/drop", "operserv/login", "memoserv/send", "memoserv/rsend",
			"memoserv/staff", "memoserv/sendall", "botserv/say", "botserv/act",
		};
		Warden::string strparams;
		if (!params.empty() && !hidden.count(cmd) && cmd.find("password") == Warden::string::npos)
		{
			for (const auto &param : params)
				strparams.append(param + " ");
			strparams.rtrim(" ");
		}

		const Warden::string scmd = source.service->nick + " " + cmd.substr(cmd.find('/') + 1).replace_all_ci("/", " ").upper();

		NLog("commands", "'%s' used %s [%s]", BuildNUHR(u).c_str(), scmd.c_str(), strparams.c_str());
	}

	EventReturn OnMessage(MessageSource &source, Warden::string &command, std::vector<Warden::string> &params, Warden::map<Warden::string> &tags) override
	{
		if (command == "INVITE" && params.size() > 1)
			UserInvite(source.GetName(), params[0], params[1]);

		return EVENT_CONTINUE;
	}
};

MODULE_INIT(OSNotify)
