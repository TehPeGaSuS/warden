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

class CommandOSModLoad final
	: public Command
{
public:
	CommandOSModLoad(Module *creator) : Command(creator, "operserv/modload", 1, 1)
	{
		this->SetDesc(_("Load a module"));
		this->SetSyntax(_("\037modname\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		const Warden::string &mname = params[0];

		ModuleReturn status = ModuleManager::LoadModule(mname, source.GetUser());
		if (status == MOD_ERR_OK)
		{
			Log(LOG_ADMIN, source, this) << "to load module " << mname;
			source.Reply(_("Module \002%s\002 loaded."), mname.c_str());
		}
		else if (status == MOD_ERR_EXISTS)
			source.Reply(_("Module \002%s\002 is already loaded."), mname.c_str());
		else
			source.Reply(_("Unable to load module \002%s\002."), mname.c_str());
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("This command loads the module named \037modname\037 from the modules directory."));
		return true;
	}
};

class CommandOSModReLoad final
	: public Command
{
public:
	CommandOSModReLoad(Module *creator) : Command(creator, "operserv/modreload", 1, 1)
	{
		this->SetDesc(_("Reload a module"));
		this->SetSyntax(_("\037modname\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		const Warden::string &mname = params[0];

		Module *m = ModuleManager::FindModule(mname);
		if (!m)
		{
			source.Reply(_("Module \002%s\002 isn't loaded."), mname.c_str());
			return;
		}

		if (!m->handle || m->GetPermanent())
		{
			source.Reply(_("Unable to remove module \002%s\002."), m->name.c_str());
			return;
		}

		Module *protocol = ModuleManager::FindFirstOf(PROTOCOL);
		if (m->type == PROTOCOL && m != protocol)
		{
			source.Reply(_("You can not reload this module directly, instead reload %s."), protocol ? protocol->name.c_str() : "(unknown)");
			return;
		}

		/* Unrecoverable */
		bool fatal = m->type == PROTOCOL;
		ModuleReturn status = ModuleManager::UnloadModule(m, source.GetUser());

		if (status != MOD_ERR_OK)
		{
			source.Reply(_("Unable to remove module \002%s\002."), mname.c_str());
			return;
		}

		status = ModuleManager::LoadModule(mname, source.GetUser());
		if (status == MOD_ERR_OK)
		{
			Log(LOG_ADMIN, source, this) << "to reload module " << mname;
			source.Reply(_("Module \002%s\002 reloaded."), mname.c_str());
		}
		else
		{
			if (fatal)
			{
				Warden::QuitReason = "Unable to reload module " + mname;
				Warden::Quitting = true;
			}
			else
				source.Reply(_("Unable to load module \002%s\002."), mname.c_str());
		}
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("This command reloads the module named \037modname\037."));
		return true;
	}
};

class CommandOSModUnLoad final
	: public Command
{
public:
	CommandOSModUnLoad(Module *creator) : Command(creator, "operserv/modunload", 1, 1)
	{
		this->SetDesc(_("Unload a module"));
		this->SetSyntax(_("\037modname\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		const Warden::string &mname = params[0];

		Module *m = ModuleManager::FindModule(mname);
		if (!m)
		{
			source.Reply(_("Module \002%s\002 isn't loaded."), mname.c_str());
			return;
		}

		if (!m->handle || m->GetPermanent() || m->type == PROTOCOL)
		{
			source.Reply(_("Unable to remove module \002%s\002."), m->name.c_str());
			return;
		}

		Log(this->owner) << "Trying to unload module [" << mname << "]";

		ModuleReturn status = ModuleManager::UnloadModule(m, source.GetUser());

		if (status == MOD_ERR_OK)
		{
			Log(LOG_ADMIN, source, this) << "to unload module " << mname;
			source.Reply(_("Module \002%s\002 unloaded."), mname.c_str());
		}
		else
			source.Reply(_("Unable to remove module \002%s\002."), mname.c_str());
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("This command unloads the module named \037modname\037."));
		return true;
	}
};

class OSModule final
	: public Module
{
	CommandOSModLoad commandosmodload;
	CommandOSModReLoad commandosmodreload;
	CommandOSModUnLoad commandosmodunload;

public:
	OSModule(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, VENDOR),
		commandosmodload(this), commandosmodreload(this), commandosmodunload(this)
	{
		this->SetPermanent(true);

	}
};

MODULE_INIT(OSModule)
