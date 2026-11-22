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
#include "modules/memoserv/service.h"

class CommandMSSendAll final
	: public Command
{
public:
	CommandMSSendAll(Module *creator) : Command(creator, "memoserv/sendall", 1, 1)
	{
		this->SetDesc(_("Send a memo to all registered users"));
		this->SetSyntax(_("\037memo-text\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		if (!MemoServ::service)
		{
			source.Reply(TRY_AGAIN_LATER, source.command.nobreak().c_str());
			return;
		}

		const Warden::string &text = params[0];

		Log(LOG_ADMIN, source, this) << "to send " << text;

		for (const auto &[_, nc] : *NickCoreList)
		{
			if (nc != source.nc)
				MemoServ::service->Send(source.GetNick(), nc->display, text);
		}

		source.Reply(_("A massmemo has been sent to all registered users."));
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Sends all registered users a memo containing \037memo-text\037."));
		return true;
	}
};

class MSSendAll final
	: public Module
{
	CommandMSSendAll commandmssendall;

public:
	MSSendAll(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, VENDOR),
		commandmssendall(this)
	{
		if (!MemoServ::service)
			throw ModuleException("No MemoServ!");
	}
};

MODULE_INIT(MSSendAll)
