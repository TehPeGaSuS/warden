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

class CommandOSKill final
	: public Command
{
public:
	CommandOSKill(Module *creator) : Command(creator, "operserv/kill", 1, 2)
	{
		this->SetDesc(_("Kill a user"));
		this->SetSyntax(_("\037user\037 [\037reason\037]"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		const Warden::string &nick = params[0];
		Warden::string reason = params.size() > 1 ? params[1] : "";

		User *u2 = User::Find(nick, true);
		if (u2 == NULL)
			source.Reply(NICK_X_NOT_IN_USE, nick.c_str());
		else if (u2->IsProtected() || u2->server == Me)
			source.Reply(ACCESS_DENIED);
		else
		{
			if (reason.empty())
				reason = "No reason specified";
			if (Config->GetModule("operserv").Get<bool>("addakiller"))
				reason = "(" + source.GetNick() + ") " + reason;
			Log(LOG_ADMIN, source, this) << "on " << u2->nick << " for " << reason;
			u2->Kill(*source.service, reason);
		}
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Allows you to kill a user from the network. "
			"Parameters are the same as for the standard /KILL "
			"command."
		));
		return true;
	}
};

class OSKill final
	: public Module
{
	CommandOSKill commandoskill;

public:
	OSKill(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, VENDOR),
		commandoskill(this)
	{

	}
};

MODULE_INIT(OSKill)
