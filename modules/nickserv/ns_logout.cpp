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
#include "modules/nickserv/service.h"

class CommandNSLogout final
	: public Command
{
public:
	CommandNSLogout(Module *creator) : Command(creator, "nickserv/logout", 0, 2)
	{
		this->SetDesc(_("Reverse the effect of the IDENTIFY command"));
		this->SetSyntax(_("[\037nickname\037 [REVALIDATE]]"), [](auto &source) { return source.IsServicesOper(); });
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{

		const Warden::string &nick = !params.empty() ? params[0] : "";
		const Warden::string &param = params.size() > 1 ? params[1] : "";

		User *u2;
		if (!source.IsServicesOper() && !nick.empty())
			this->OnSyntaxError(source, "");
		else if (!(u2 = (!nick.empty() ? User::Find(nick, true) : source.GetUser())))
			source.Reply(NICK_X_NOT_IN_USE, !nick.empty() ? nick.c_str() : source.GetNick().c_str());
		else if (!nick.empty() && u2->IsServicesOper())
			source.Reply(_("You can't logout %s, they are a Services Operator."), nick.c_str());
		else
		{
			u2->super_admin = false; /* Don't let people logout and remain a SuperAdmin */
			Log(LOG_COMMAND, source, this) << "to logout " << u2->nick;

			/* Remove founder status from this user in all channels */
			if (!nick.empty())
				source.Reply(_("Nick %s has been logged out."), nick.c_str());
			else
				source.Reply(_("Your nick has been logged out."));

			IRCD->SendLogout(u2);
			u2->RemoveMode(source.service, "REGISTERED");
			u2->Logout();

			/* Send out an event */
			FOREACH_MOD(OnNickLogout, (u2));

			// Logging yourself out (or an oper's REVALIDATE) puts the nick back
			// under protection, as if the user had just taken it. Certificate
			// auto-login is off until they identify again, or it would log
			// them straight back in.
			const auto revalidate = nick.empty() || param.equals_ci("REVALIDATE");
			if (revalidate && NickServ::service)
			{
				u2->Extend<bool>("LOGGEDOUT");
				NickServ::service->Validate(u2);
			}
		}
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");

		if (source.IsServicesOper())
		{
			source.Reply(_(
				"Without a parameter, reverses the effect of the \002IDENTIFY\002 "
				"command, i.e. make you not recognized as the real owner of the nick "
				"anymore. If the nick you are using is protected, you have to "
				"identify again or your nick will be changed."
				"\n\n"
				"With a parameter, does the same for the given nick. If you "
				"specify \002REVALIDATE\002 as well, services will ask the given nick "
				"to re-identify. This is limited to \002Services Operators\002."
			));
		}
		else
		{
			source.Reply(_(
				"Reverses the effect of the \002IDENTIFY\002 command, i.e. make you not "
				"recognized as the real owner of the nick anymore. If the nick you are "
				"using is protected, you have to identify again or your nick will be "
				"changed."
			));
		}
		return true;
	}
};

class NSLogout final
	: public Module
{
	CommandNSLogout commandnslogout;
	ExtensibleItem<bool> loggedout;

public:
	NSLogout(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, VENDOR),
		commandnslogout(this), loggedout(this, "LOGGEDOUT")
	{

	}

	void OnNickIdentify(User *u) override
	{
		loggedout.Unset(u);
	}
};

MODULE_INIT(NSLogout)
