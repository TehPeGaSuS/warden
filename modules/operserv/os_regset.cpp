// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2020 Matt Schatz (genius3000) <genius3000@g3k.solutions>
// Copyright (C) 2026 Warden Contributors
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// SPDX-License-Identifier: GPL-2.0-only

// Lets operators change when a nick, account or channel was registered, e.g.
// after moving it from another network. Based on genius3000's third-party
// os_regset.

#include "module.h"

#include <ctime>
#include <iomanip>
#include <sstream>

class CommandOSRegSet final
	: public Command
{
	// A Unix timestamp, or a UTC date as YYYY-MM-DD or YYYY-MM-DD HH:MM.
	static time_t ParseTime(const Warden::string &when)
	{
		if (when.is_pos_number_only())
			return Warden::Convert<time_t>(when, 0);

		std::tm tm = {};
		std::istringstream in(when.str());
		in >> std::get_time(&tm, when.find(':') != Warden::string::npos ? "%Y-%m-%d %H:%M" : "%Y-%m-%d");
		if (in.fail())
			return 0;
		return timegm(&tm);
	}

	void Report(CommandSource &source, const char *what, const Warden::string &name, time_t ts)
	{
		Log(LOG_ADMIN, source, this) << "to set the registration time of " << what << " " << name << " to " << Warden::strftime(ts, nullptr, true) << " (" << ts << ")";
	}

public:
	CommandOSRegSet(Module *creator)
		: Command(creator, "operserv/regset", 3, 3)
	{
		this->SetDesc(_("Change when a nick, account or channel was registered"));
		this->SetSyntax(_("{NICK|ACCOUNT|CHAN} \037name\037 \037time\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		const auto &type = params[0];
		const auto &target = params[1];
		const auto ts = ParseTime(params[2]);
		if (ts <= 0 || ts > Warden::CurTime)
		{
			source.Reply(_("\002%s\002 is not a valid time. Give a Unix timestamp or a date such as \0022019-05-01\002 (UTC), not in the future."), params[2].c_str());
			return;
		}
		const auto pretty = Warden::strftime(ts, source.GetAccount());

		if (type.equals_ci("NICK"))
		{
			auto *na = NickAlias::Find(target);
			if (!na)
			{
				source.Reply(NICK_X_NOT_REGISTERED, target.c_str());
				return;
			}

			na->registered = ts;
			Report(source, "nick", na->nick, ts);
			source.Reply(_("Registration time of nick \002%s\002 set to %s."), na->nick.c_str(), pretty.c_str());
		}
		else if (type.equals_ci("ACCOUNT"))
		{
			auto *nc = NickCore::Find(target);
			if (!nc)
			{
				if (auto *na = NickAlias::Find(target))
					nc = na->nc;
			}
			if (!nc)
			{
				source.Reply(NICK_X_NOT_REGISTERED, target.c_str());
				return;
			}

			// The account and every nick grouped to it.
			nc->registered = ts;
			for (auto *na : *nc->aliases)
				na->registered = ts;

			Report(source, "account", nc->display, ts);
			source.Reply(_("Registration time of account \002%s\002 and its %zu nick(s) set to %s."), nc->display.c_str(), nc->aliases->size(), pretty.c_str());
		}
		else if (type.equals_ci("CHAN"))
		{
			auto *ci = ChannelInfo::Find(target);
			if (!ci)
			{
				source.Reply(CHAN_X_NOT_REGISTERED, target.c_str());
				return;
			}

			ci->registered = ts;
			Report(source, "channel", ci->name, ts);
			source.Reply(_("Registration time of channel \002%s\002 set to %s."), ci->name.c_str(), pretty.c_str());
		}
		else
			this->OnSyntaxError(source, "");
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Changes when a nick, account or channel was registered, e.g. "
			"after moving it from another network."
			"\n\n"
			"\002NICK\002 changes one nick. \002ACCOUNT\002 changes the account "
			"and every nick grouped to it. \002CHAN\002 changes a channel."
			"\n\n"
			"\037time\037 is a Unix timestamp or a UTC date such as "
			"\0022019-05-01\002 or \0022019-05-01 14:30\002. It can't be in "
			"the future."
		));
		return true;
	}
};

class OSRegSet final
	: public Module
{
	CommandOSRegSet commandosregset;

public:
	OSRegSet(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, VENDOR)
		, commandosregset(this)
	{
	}
};

MODULE_INIT(OSRegSet)
