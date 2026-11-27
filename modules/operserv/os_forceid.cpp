// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2014 DukePyrolator, Andromeda
// Copyright (C) 2026 Warden Contributors
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// SPDX-License-Identifier: GPL-2.0-only

// Identifies an online user to the registered nick they are using, without
// their password. Based on the third-party os_forceid by DukePyrolator and
// Andromeda (original concept by n00bie).

#include "module.h"

class CommandOSForceID final
	: public Command
{
public:
	CommandOSForceID(Module *creator) : Command(creator, "operserv/forceid", 1, 1)
	{
		this->SetDesc(_("Identify a user to their nick without a password"));
		this->SetSyntax(_("\037nick\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		const Warden::string &nick = params[0];

		User *u = User::Find(nick, true);
		if (!u)
		{
			source.Reply(NICK_X_NOT_IN_USE, nick.c_str());
			return;
		}

		if (u->server == Me)
		{
			source.Reply(ACCESS_DENIED);
			return;
		}

		NickAlias *na = NickAlias::Find(u->nick);
		if (!na)
		{
			source.Reply(NICK_X_NOT_REGISTERED, u->nick.c_str());
			return;
		}

		if (na->nc->HasExt("NS_SUSPENDED"))
		{
			source.Reply(NICK_X_SUSPENDED, na->nick.c_str());
			return;
		}

		// Same rule as RESETPASS: an unconfirmed registration has not shown
		// it owns its email address yet.
		if (na->nc->HasExt("UNCONFIRMED"))
		{
			source.Reply(_("The registration of \002%s\002 has not been confirmed yet."), na->nick.c_str());
			return;
		}

		if (u->Account() == na->nc)
		{
			source.Reply(_("\002%s\002 is already identified to \002%s\002."), u->nick.c_str(), na->nc->display.c_str());
			return;
		}

		Log(LOG_ADMIN, source, this) << "on " << u->nick << " (" << u->GetMask() << ") to " << na->nc->display;
		u->Identify(na);
		u->SendMessage(source.service, _("You have been identified to \002%s\002 by a services operator."), na->nc->display.c_str());
		source.Reply(_("\002%s\002 is now identified to \002%s\002."), u->nick.c_str(), na->nc->display.c_str());
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Identifies an online user to the registered nick they are "
			"using, without asking for its password, e.g. for a user who "
			"can't log in. The user is told it was done by a services "
			"operator. Suspended nicks and registrations that are not "
			"confirmed yet are refused."
		));
		return true;
	}
};

class OSForceID final
	: public Module
{
	CommandOSForceID commandosforceid;

public:
	OSForceID(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, VENDOR),
		commandosforceid(this)
	{
	}
};

MODULE_INIT(OSForceID)
