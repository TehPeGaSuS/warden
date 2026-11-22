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

class CommandOSUpdate final
	: public Command
{
public:
	CommandOSUpdate(Module *creator) : Command(creator, "operserv/update", 0, 0)
	{
		this->SetDesc(_("Force the services databases to be updated immediately"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		Log(LOG_ADMIN, source, this);
		source.Reply(_("Updating databases."));
		Warden::SaveDatabases();
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Causes services to update all database files as soon as you send the command."));
		return true;
	}
};

class OSUpdate final
	: public Module
{
	CommandOSUpdate commandosupdate;

public:
	OSUpdate(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, VENDOR),
		commandosupdate(this)
	{

	}
};

MODULE_INIT(OSUpdate)
