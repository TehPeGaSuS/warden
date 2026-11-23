// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2018 Matt Schatz (genius3000) <genius3000@g3k.solutions>
// Copyright (C) 2026 Warden Contributors
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// SPDX-License-Identifier: GPL-2.0-only

// InspIRCd only: copies G-, Z- and R-lines that opers set on the IRCd into
// the AKILL list (and removes them again), so services and the IRCd agree.
// Based on genius3000's third-party m_xlinetoakill.

#include "module.h"

static ServiceReference<XLineManager> akills("XLineManager", "xlinemanager/sgline");

class XLineToAkill final
	: public Module
{
	BotInfo *OperServ = nullptr;

public:
	XLineToAkill(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, VENDOR)
	{
		if (!IRCD || IRCD->GetProtocolName().find("InspIRCd") == Warden::string::npos)
			throw ModuleException("This module only works with InspIRCd.");
	}

	void OnReload(Configuration::Conf &conf) override
	{
		OperServ = conf.GetClient("OperServ");
	}

	EventReturn OnMessage(MessageSource &source, Warden::string &command, std::vector<Warden::string> &params, Warden::map<Warden::string> &tags) override
	{
		if ((command != "ADDLINE" && command != "DELLINE") || params.size() < 2 || !akills)
			return EVENT_CONTINUE;

		const auto &type = params[0];
		auto mask = params[1];
		if (type == "R")
		{
			// R-lines come as n!u@h\sreal\sname; AKILLs want /n!u@h#real name/,
			// which only works with a regex engine.
			if (Config->GetBlock("options").Get<const Warden::string>("regexengine").empty())
				return EVENT_CONTINUE;
			const auto space = mask.find("\\s");
			if (space != Warden::string::npos)
			{
				mask = mask.replace(space, 2, "#");
				mask = mask.replace_all_cs("\\s", " ");
			}
			mask = "/" + mask + "/";
		}
		else if (type == "Z")
			mask = "*@" + mask;
		else if (type != "G")
			return EVENT_CONTINUE;

		if (command == "ADDLINE" && params.size() >= 6)
		{
			// Our own AKILLs come back like this too.
			if (akills->HasEntry(mask))
				return EVENT_CONTINUE;

			const auto &setby = params[2];
			const auto &reason = params[5];
			const auto settime = Warden::TryConvert<time_t>(params[3]);
			const auto duration = Warden::TryConvert<time_t>(params[4]);
			if (!settime || !duration)
			{
				Log(OperServ, "akill/sync") << "Ignoring " << type << "-line on " << mask << " with a malformed set time or duration (" << params[3] << ", " << params[4] << ")";
				return EVENT_CONTINUE;
			}

			const auto expires = *duration ? *settime + *duration : 0;
			if (expires && expires <= Warden::CurTime)
				return EVENT_CONTINUE;

			auto *x = new XLine(mask, setby, expires, reason);
			if (Config->GetModule("operserv").Get<bool>("akillids"))
				x->id = XLineManager::GenerateUID();
			akills->AddXLine(x);

			Log(OperServ, "akill/sync") << "Added an AKILL on " << mask << " (" << reason << ") from " << setby << "'s " << type << "-line, expires " << (expires ? "in " + Warden::Duration(expires - Warden::CurTime) : "never");
		}
		else if (command == "DELLINE")
		{
			auto *x = akills->HasEntry(mask);
			if (!x)
				return EVENT_CONTINUE;

			akills->DelXLine(x);
			Log(OperServ, "akill/sync") << "Removed the AKILL on " << mask << " as its " << type << "-line was removed";
		}

		// Let the protocol module and others see it too.
		return EVENT_CONTINUE;
	}
};

MODULE_INIT(XLineToAkill)
