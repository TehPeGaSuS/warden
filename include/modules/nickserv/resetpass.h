// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2026 Warden Contributors
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// SPDX-License-Identifier: GPL-2.0-only

#pragma once

#define NICKSERV_RESETPASS_EXT "reset"

namespace NickServ
{
	/** A pending password reset (ns_resetpass), kept on the account until it
	 * is confirmed, expires, or a new password is set. Not saved.
	 */
	struct ResetInfo final
	{
		Warden::string code;
		time_t time;
	};
}
