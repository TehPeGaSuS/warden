// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2026 Warden Contributors
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// SPDX-License-Identifier: GPL-2.0-only

// Tells users when someone else adds them to a channel's access list or makes
// them its founder or successor (anope/anope#503): a notice if they are
// online, otherwise a memo (which MemoServ mails if they asked for that).

#include "module.h"
#include "modules/memoserv/service.h"

class CSAccessNotify final
	: public Module
{
	// Founder and successor before a SET FOUNDER/SUCCESSOR, to see what changed.
	Warden::string pending_channel;
	NickCore *old_founder = nullptr, *old_successor = nullptr;

	static bool IsSetCommand(const Command *command)
	{
		return command->name == "chanserv/set/founder" || command->name == "chanserv/set/successor";
	}

	// Notices every user logged into nc, or memos the account if none are.
	void Notify(NickCore *nc, CommandSource &source, const char *message, const Warden::string &channel, const Warden::string &extra = "")
	{
		if (!nc || nc == source.GetAccount())
			return;

		auto *chanserv = Config->GetClient("ChanServ");
		bool told = false;
		for (auto *u : nc->users)
		{
			if (chanserv)
				u->SendMessage(chanserv, message, source.GetNick().c_str(), channel.c_str(), extra.c_str());
			told = true;
		}

		if (!told && MemoServ::service && chanserv && Config->GetModule(this).Get<bool>("memo", "yes"))
		{
			auto text = Warden::Format(Language::Translate(nc, message), source.GetNick().c_str(), channel.c_str(), extra.c_str());
			MemoServ::service->Send(chanserv->nick, nc->display, text, true);
		}
	}

public:
	CSAccessNotify(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, VENDOR)
	{
	}

	void OnAccessAdd(ChannelInfo *ci, CommandSource &source, ChanAccess *access, bool migrated) override
	{
		if (migrated)
			return;

		auto *nc = access->GetAccount();
		if (nc)
		{
			Notify(nc, source, _("%s added you to the access list of \002%s\002 (%s). If you don't want this, remove yourself with \002ACCESS DEL\002, \002XOP DEL\002 or \002FLAGS\002."),
				ci->name, access->AccessSerialize());
			return;
		}

		// A mask such as nick!*@*: tell that nick if it is online and the
		// nick part has no wildcards.
		auto nick = access->Mask();
		auto bang = nick.find('!');
		if (bang != Warden::string::npos)
			nick = nick.substr(0, bang);
		if (nick.empty() || nick.find_first_of("*?") != Warden::string::npos)
			return;
		auto *u = User::Find(nick, true);
		auto *chanserv = Config->GetClient("ChanServ");
		if (u && chanserv && u != source.GetUser())
			u->SendMessage(chanserv, _("%s added you to the access list of \002%s\002 (%s) by your nick; register it to keep that access safe."), source.GetNick().c_str(), ci->name.c_str(), access->AccessSerialize().c_str());
	}

	EventReturn OnPreCommand(CommandSource &source, Command *command, std::vector<Warden::string> &params) override
	{
		pending_channel.clear();
		if (!IsSetCommand(command) || params.empty())
			return EVENT_CONTINUE;

		auto *ci = ChannelInfo::Find(params[0]);
		if (ci)
		{
			pending_channel = ci->name;
			old_founder = ci->GetFounder();
			old_successor = ci->GetSuccessor();
		}
		return EVENT_CONTINUE;
	}

	void OnPostCommand(CommandSource &source, Command *command, const std::vector<Warden::string> &params) override
	{
		if (!IsSetCommand(command) || pending_channel.empty())
			return;

		auto *ci = ChannelInfo::Find(pending_channel);
		pending_channel.clear();
		if (!ci)
			return;

		if (ci->GetFounder() && ci->GetFounder() != old_founder)
			Notify(ci->GetFounder(), source, _("%s made you the founder of \002%s\002."), ci->name);
		if (ci->GetSuccessor() && ci->GetSuccessor() != old_successor)
			Notify(ci->GetSuccessor(), source, _("%s made you the successor of \002%s\002. If you don't want this, ask a channel founder to change it."), ci->name);
	}
};

MODULE_INIT(CSAccessNotify)
