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

// Confirmation links for emails. The webcpanel module provides this service:
// Create() stores a random token for a pending confirmation and returns the
// link to put in the email, which opens a page with a Confirm button.

namespace WebLink
{
	// What a link confirms.
	enum class Type
	{
		REGISTER,  // nickserv/confirm/register
		EMAIL,     // nickserv/confirm/email
		RESETPASS, // nickserv/confirm/resetpass, then a new password
	};

	class Service
		: public ::Service
	{
	public:
		Service(Module *o)
			: ::Service(o, "WebLink::Service", "weblink")
		{
		}

		// Creates a link for the given nick and confirmation code, valid for
		// expiry seconds, replacing any earlier link of the same type for that
		// account. Returns an empty string if links are not configured.
		virtual Warden::string Create(Type type, const NickAlias *na, const Warden::string &code, time_t expiry) = 0;

		// Removes every link of the given type for an account.
		virtual void Revoke(Type type, const NickCore *nc) = 0;
	};

	// The link for a confirmation email, or an empty string.
	inline Warden::string Create(Type type, const NickAlias *na, const Warden::string &code, time_t expiry)
	{
		static ServiceReference<Service> service("WebLink::Service", "weblink");
		return service ? service->Create(type, na, code, expiry) : "";
	}
}
