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

class CommandOSConfig final
	: public Command
{
public:
	CommandOSConfig(Module *creator) : Command(creator, "operserv/config", 1, 4)
	{
		this->SetDesc(_("View and change configuration file settings"));
		this->SetSyntax(_("{\037MODIFY\037|\037VIEW\037} [\037block name\037 \037item name\037 \037item value\037]"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		const Warden::string &what = params[0];

		if (what.equals_ci("MODIFY") && params.size() > 3)
		{
			if (!source.HasPriv("operserv/config"))
			{
				source.Reply(ACCESS_DENIED);
				return;
			}

			auto *block = Config->GetMutableBlock(params[1]);
			if (!block)
				block = &Config->GetModule(params[1]);

			if (!block)
			{
				source.Reply(_("There is no such configuration block %s."), params[1].c_str());
				return;
			}

			block->Set(params[2], params[3]);

			Log(LOG_ADMIN, source, this) << "to change the configuration value of " << params[1] << ":" << params[2] << " to " << params[3];
			source.Reply(_("Value of %s:%s changed to %s"), params[1].c_str(), params[2].c_str(), params[3].c_str());
		}
		else if (what.equals_ci("VIEW"))
		{
			/* Blocks we should show */
			const Warden::string show_blocks[] = { "serverinfo", "networkinfo", "options", "" };

			Log(LOG_ADMIN, source, this) << "VIEW";

			for (unsigned i = 0; !show_blocks[i].empty(); ++i)
			{
				const auto &block = Config->GetBlock(show_blocks[i]);
				const auto &items = block.GetItems();

				ListFormatter lflist(source.GetAccount());
				lflist.AddColumn(_("Name")).AddColumn(_("Value"));
				lflist.SetFlexible(_("\002{name}\002 = {value}"));

				for (const auto &[name, value] : items)
				{
					ListFormatter::ListEntry entry;
					entry["Name"] = name;
					entry["Value"] = value;
					lflist.AddEntry(entry);
				}

				source.Reply(_("%s settings:"), block.GetName().c_str());
				lflist.SendTo(source);
				source.Reply(" ");
			}

			ListFormatter lflist(source.GetAccount());
			lflist.AddColumn(_("Module Name")).AddColumn(_("Name")).AddColumn(_("Value"));
			lflist.SetFlexible(_("\002{}{module_name}}:{name}\002 = {value}"));

			for (const auto &[_,  block] : Config->GetBlocks("module"))
			{
				const auto &items = block.GetItems();

				if (items.size() <= 1)
					continue;

				ListFormatter::ListEntry entry;
				entry["Module Name"] = block.Get<Warden::string>("name");

				for (const auto &[name, value] : items)
				{
					entry["Name"] = name;
					entry["Value"] = value;
					lflist.AddEntry(entry);
				}
			}
			source.Reply(_("Module settings:"));
			lflist.SendTo(source);
			source.Reply(_("End of configuration."));
		}
		else
			this->OnSyntaxError(source, what);
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Allows you to change and view configuration settings. "
			"Settings changed by this command are temporary and will not be reflected "
			"back into the configuration file, and will be lost if Warden is shut down, "
			"restarted, or the configuration is reloaded."
		));

		ExampleWrapper examples;
		examples.AddEntry("MODIFY nickserv regdelay 15m", _(
			"Changes the registration delay to 15 minutes."
		));
		examples.AddEntry("VIEW", _(
			"Shows the current server configuration."
		));
		examples.SendTo(source);

		return true;
	}
};

class OSConfig final
	: public Module
{
	CommandOSConfig commandosconfig;

public:
	OSConfig(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, VENDOR),
		commandosconfig(this)
	{

	}
};

MODULE_INIT(OSConfig)
