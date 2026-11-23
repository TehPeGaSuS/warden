// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) Azander
// Copyright (C) 2026 Warden Contributors
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// SPDX-License-Identifier: GPL-2.0-only

// Lists users who are in no channel (often idle bots or drones), and can
// join, kill or AKILL them all at once. Based on Azander's third-party
// os_notinchan.

#include "module.h"

static ServiceReference<XLineManager> akills("XLineManager", "xlinemanager/sgline");

class CommandOSNotInChan final
	: public Command
{
	// Users who are in no channel, leaving out opers, services and anyone
	// who connected too recently to have joined anything yet.
	std::vector<User *> Find()
	{
		const auto minage = Config->GetModule(this->owner).Get<time_t>("minage", "1m");

		Warden::map<User *> sorted;
		for (const auto &[nick, u] : UserListByNick)
		{
			if (!u->chans.empty() || u->Quitting())
				continue;
			if (u->server == Me || u->server->IsULined() || u->HasMode("OPER") || u->IsServicesOper())
				continue;
			if (Warden::CurTime - u->signon < minage)
				continue;
			sorted[nick] = u;
		}

		std::vector<User *> users;
		for (const auto &[_, u] : sorted)
			users.push_back(u);
		return users;
	}

	void DoList(CommandSource &source, const std::vector<User *> &users)
	{
		if (users.empty())
		{
			source.Reply(_("No users are outside every channel."));
			return;
		}

		ListFormatter list(source.GetAccount());
		list.AddColumn(_("Nick")).AddColumn(_("Mask")).AddColumn(_("Realname"));
		list.SetFlexible(_("\002{nick}\002 ({mask}) {realname}"));
		for (auto *u : users)
		{
			ListFormatter::ListEntry entry;
			entry["Nick"] = u->nick;
			entry["Mask"] = u->GetIdent() + "@" + u->host;
			entry["Realname"] = u->realname;
			list.AddEntry(entry);
		}

		source.Reply(_("Users in no channel:"));
		list.SendTo(source);
		source.Reply(_("End of list - %zu user(s)."), users.size());
	}

	void DoJoin(CommandSource &source, const std::vector<User *> &users)
	{
		if (!IRCD->CanSVSJoin)
		{
			source.Reply(_("Your IRCd does not support SVSJOIN."));
			return;
		}

		const auto chan = Config->GetModule(this->owner).Get<const Warden::string>("idlechan", "#idle");
		for (auto *u : users)
			IRCD->SendSVSJoin(*source.service, u, chan, "");

		Log(LOG_ADMIN, source, this) << "to join " << users.size() << " user(s) to " << chan;
		source.Reply(_("Joined \002%zu\002 user(s) to \002%s\002."), users.size(), chan.c_str());
	}

	void DoKill(CommandSource &source, const std::vector<User *> &users, Warden::string reason)
	{
		if (reason.empty())
			reason = Config->GetModule(this->owner).Get<const Warden::string>("killreason", "Not in any channel");

		for (auto *u : users)
			u->Kill(*source.service, reason);

		Log(LOG_ADMIN, source, this) << "to kill " << users.size() << " user(s) (" << reason << ")";
		source.Reply(_("Killed \002%zu\002 user(s)."), users.size());
	}

	void DoAkill(CommandSource &source, const std::vector<User *> &users, Warden::string reason)
	{
		if (!akills)
		{
			source.Reply(_("AKILLs are not available (is os_akill loaded?)."));
			return;
		}

		const auto &block = Config->GetModule(this->owner);
		if (reason.empty())
			reason = block.Get<const Warden::string>("akillreason", "Not in any channel");
		const auto expiry = block.Get<time_t>("akillexpire", "1h");
		const auto expires = expiry ? Warden::CurTime + expiry : 0;

		std::set<Warden::string> masks;
		std::set<User *> targets(users.begin(), users.end());
		for (auto *u : users)
			masks.insert("*@" + u->host);

		size_t added = 0, shared = 0;
		for (const auto &mask : masks)
		{
			// Never ban a host that other users share (a bouncer, a webchat
			// gateway, an oper's own host...).
			auto *probe = new XLine(mask, source.GetNick(), expires, reason);
			auto others = false;
			for (const auto &[_, u] : UserListByNick)
			{
				if (!targets.count(u) && akills->Check(u, probe))
				{
					others = true;
					break;
				}
			}
			delete probe;
			if (others)
			{
				++shared;
				continue;
			}

			if (akills->HasEntry(mask) || !akills->CanAdd(source, mask, expires, reason))
				continue;

			auto *x = new XLine(mask, source.GetNick(), expires, reason);
			if (Config->GetModule("operserv").Get<bool>("akillids"))
				x->id = XLineManager::GenerateUID();

			EventReturn MOD_RESULT;
			FOREACH_RESULT(OnAddXLine, MOD_RESULT, (source, x, akills));
			if (MOD_RESULT == EVENT_STOP)
			{
				delete x;
				continue;
			}

			akills->AddXLine(x);
			akills->Send(nullptr, x);
			++added;
		}

		Log(LOG_ADMIN, source, this) << "to AKILL " << users.size() << " user(s) with " << added << " AKILL(s) (" << reason << "), expires in " << (expires ? Warden::Duration(expiry) : "never");
		source.Reply(_("Added \002%zu\002 AKILL(s) for \002%zu\002 user(s)."), added, users.size());
		if (shared)
			source.Reply(_("Skipped \002%zu\002 host(s) that other users share; use \002KILL\002 or AKILL those users by hand."), shared);
		if (Warden::ReadOnly)
			source.Reply(READ_ONLY_MODE);
	}

public:
	CommandOSNotInChan(Module *creator)
		: Command(creator, "operserv/notinchan", 0, 2)
	{
		this->SetDesc(_("List, join, kill or AKILL users who are in no channel"));
		this->SetSyntax(_("[LIST | JOIN | KILL [\037reason\037] | AKILL [\037reason\037]]"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		const auto subcommand = params.empty() ? "LIST" : params[0];
		const auto reason = params.size() > 1 ? params[1] : "";

		if (subcommand.equals_ci("LIST"))
			DoList(source, Find());
		else if (subcommand.equals_ci("JOIN"))
			DoJoin(source, Find());
		else if (subcommand.equals_ci("KILL"))
			DoKill(source, Find(), reason);
		else if (subcommand.equals_ci("AKILL"))
			DoAkill(source, Find(), reason);
		else
			this->OnSyntaxError(source, "");
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		const auto &block = Config->GetModule(this->owner);
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
				"Finds users who are in no channel, which is often a sign of "
				"idle bots or drones. IRC operators, services and users who "
				"connected less than %s ago are never included."
				"\n\n"
				"\002LIST\002 (the default) shows them. \002JOIN\002 makes them "
				"all join \002%s\002. \002KILL\002 disconnects them. \002AKILL\002 "
				"adds an AKILL on each of their hosts for %s, except hosts that "
				"other users share."
			),
			Warden::Duration(block.Get<time_t>("minage", "1m"), source.GetAccount()).c_str(),
			block.Get<const Warden::string>("idlechan", "#idle").c_str(),
			Warden::Duration(block.Get<time_t>("akillexpire", "1h"), source.GetAccount()).c_str());
		return true;
	}
};

class OSNotInChan final
	: public Module
{
	CommandOSNotInChan commandosnotinchan;

public:
	OSNotInChan(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, VENDOR)
		, commandosnotinchan(this)
	{
	}
};

MODULE_INIT(OSNotInChan)
