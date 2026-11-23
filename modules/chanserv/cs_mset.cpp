// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2026 Warden Contributors
// Inspired by ns_massset by LEthaLity and PeGaSuS.
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// SPDX-License-Identifier: GPL-2.0-only

#include "module.h"
#include "modules/mset.h"

class CommandCSMSet final
	: public Command
{
public:
	CommandCSMSet(Module *creator) : Command(creator, "chanserv/mset", 1, 2)
	{
		this->SetDesc(_("Set an option for every registered channel"));
		this->SetSyntax(_("\037option\037 [\037parameters\037]"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		std::vector<Warden::string> targets;
		for (const auto &[_, ci] : *RegisteredChannelList)
			targets.push_back(ci->name);
		MSet::Run(source, this, "SET", params[0], params.size() > 1 ? params[1] : "", targets, { "chanserv/set/description", "chanserv/set/founder", "chanserv/set/misc", "chanserv/set/successor" }, "channel");
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Runs \002SET \037option\037 \037channel\037 \037parameters\037\002 for every registered channel, e.g. after changing a default in the configuration. Any SET option can be used except FOUNDER, SUCCESSOR, DESCRIPTION and the free-text ones such as URL. "
			"Each change goes through the normal \002SET\002 command, so it is "
			"checked exactly as if you ran it yourself, and you get a summary of the "
			"replies instead of one per channel."
			"\n\n"
			"Example:\n"
			"    \002MSET SECUREOPS ON\002"
		));
		return true;
	}
};

class CSMSetModule final
	: public Module
{
	CommandCSMSet command;

public:
	CSMSetModule(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, VENDOR)
		, command(this)
	{
		// Quieten the per-channel log lines before anything else sees them.
		ModuleManager::SetPriority(this, I_OnLog, PRIORITY_FIRST);
	}

	void OnLog(Log *l) override
	{
		MSet::Quieten(l);
	}
};

MODULE_INIT(CSMSetModule)
