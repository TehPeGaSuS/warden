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

class BSAutoAssign final
	: public Module
{
public:
	BSAutoAssign(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, VENDOR)
	{
	}

	void OnChanRegistered(ChannelInfo *ci) override
	{
		const Warden::string &bot = Config->GetModule(this).Get<const Warden::string>("bot");
		if (bot.empty())
			return;

		BotInfo *bi = BotInfo::Find(bot, true);
		if (bi == NULL)
		{
			Log(this) << "bs_autoassign is configured to assign bot " << bot << ", but it does not exist?";
			return;
		}

		bi->Assign(NULL, ci);
	}
};

MODULE_INIT(BSAutoAssign)
