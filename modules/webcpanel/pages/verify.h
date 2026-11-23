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

#include "modules/httpd.h"
#include "modules/weblink.h"

namespace WebCPanel
{

// A pending confirmation that an emailed link can complete.
struct WebToken final
	: Serializable
{
	Warden::string token;
	WebLink::Type type = WebLink::Type::REGISTER;
	Warden::string nick;
	uint64_t account = 0;
	Warden::string code;
	time_t expires = 0;

	WebToken();
	~WebToken() override;

	// The nick the link is for, if it still belongs to the same account.
	NickAlias *GetNick() const;
};

struct WebTokenType final
	: Serialize::Type
{
	WebTokenType();
	void Serialize(Serializable *obj, Serialize::Data &data) const override;
	Serializable *Unserialize(Serializable *obj, Serialize::Data &data) const override;
};

class WebLinkService final
	: public WebLink::Service
{
public:
	WebLinkService(Module *m) : WebLink::Service(m) { }

	Warden::string Create(WebLink::Type type, const NickAlias *na, const Warden::string &code, time_t expiry) override;
	void Revoke(WebLink::Type type, const NickCore *nc) override;

	// A token that is still valid, or nullptr (expired ones are removed).
	static WebToken *Find(const Warden::string &token);

	// Removes expired tokens.
	static void Expire();
};

// The page emailed links open: shows what will be confirmed and a Confirm
// button, and only acts on the button (a POST), so mail scanners that open
// links can't confirm anything.
class Verify final
	: public WebPanelPage
{
public:
	Verify(const Warden::string &u) : WebPanelPage(u) { }

	bool OnRequest(HTTP::Provider *, const Warden::string &, HTTP::Client *, HTTP::Message &, HTTP::Reply &) override;
};

}
