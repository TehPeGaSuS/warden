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

#include "../webcpanel.h"
#include "modules/nickserv/resetpass.h"

#define WEBTOKEN_TYPE "WebToken"

using namespace WebCPanel;

namespace
{
	// Tokens are case sensitive.
	std::map<Warden::string, WebToken *> tokens;

	const char *TypeName(WebLink::Type type)
	{
		switch (type)
		{
			case WebLink::Type::REGISTER:
				return "REGISTER";
			case WebLink::Type::EMAIL:
				return "EMAIL";
			case WebLink::Type::RESETPASS:
				return "RESETPASS";
		}
		return "";
	}

	bool ParseType(const Warden::string &name, WebLink::Type &type)
	{
		for (auto t : { WebLink::Type::REGISTER, WebLink::Type::EMAIL, WebLink::Type::RESETPASS })
		{
			if (name.equals_ci(TypeName(t)))
			{
				type = t;
				return true;
			}
		}
		return false;
	}
}

WebToken::WebToken()
	: Serializable(WEBTOKEN_TYPE)
{
}

WebToken::~WebToken()
{
	auto it = tokens.find(this->token);
	if (it != tokens.end() && it->second == this)
		tokens.erase(it);
}

NickAlias *WebToken::GetNick() const
{
	auto *na = NickAlias::Find(this->nick);
	return na && na->nc->GetId() == this->account ? na : nullptr;
}

bool WebToken::IsPending() const
{
	// A reset link only works while ns_resetpass still has the reset pending:
	// finishing the reset on IRC, changing the password, using a recovery key
	// or restarting services all end it.
	if (this->type != WebLink::Type::RESETPASS)
		return true;
	auto *na = this->GetNick();
	if (!na)
		return false;
	// The pending reset must be the one this link was sent for: a newer
	// request replaces it even when the old link wasn't revoked.
	const auto *ri = na->nc->GetExt<::NickServ::ResetInfo>(NICKSERV_RESETPASS_EXT);
	return ri && ri->code.equals_cs(this->code);
}

WebTokenType::WebTokenType()
	: Serialize::Type(WEBTOKEN_TYPE)
{
}

void WebTokenType::Serialize(Serializable *obj, Serialize::Data &data) const
{
	const auto *wt = static_cast<const WebToken *>(obj);
	data.Store("token", wt->token);
	data.Store("type", TypeName(wt->type));
	data.Store("nick", wt->nick);
	data.Store("account", wt->account);
	data.Store("code", wt->code);
	data.Store("expires", wt->expires);
}

Serializable *WebTokenType::Unserialize(Serializable *obj, Serialize::Data &data) const
{
	WebLink::Type type;
	if (!ParseType(data.Load("type"), type))
		return nullptr;

	auto *wt = obj ? warden_dynamic_static_cast<WebToken *>(obj) : new WebToken();
	if (!obj)
	{
		wt->token = data.Load("token");
		if (wt->token.empty() || tokens.count(wt->token))
		{
			delete wt;
			return nullptr;
		}
		tokens[wt->token] = wt;
	}

	wt->type = type;
	wt->nick = data.Load("nick");
	wt->account = data.Load<uint64_t>("account");
	wt->code = data.Load("code");
	wt->expires = data.Load<time_t>("expires");
	return wt;
}

Warden::string WebLinkService::Create(WebLink::Type type, const NickAlias *na, const Warden::string &code, time_t expiry)
{
	if (!na || code.empty())
		return "";

	auto weburl = Config->GetBlock("mail").Get<const Warden::string>("weburl");
	if (weburl.empty())
		return "";
	while (!weburl.empty() && weburl[weburl.length() - 1] == '/')
		weburl.erase(weburl.length() - 1);

	// One pending link of each type per account: a new email replaces the
	// link in the old one.
	this->Revoke(type, na->nc);

	auto *wt = new WebToken();
	do
		wt->token = Warden::Random(32);
	while (tokens.count(wt->token));
	wt->type = type;
	wt->nick = na->nick;
	wt->account = na->nc->GetId();
	wt->code = code;
	wt->expires = expiry > 0 ? Warden::CurTime + expiry : 0;
	tokens[wt->token] = wt;

	return weburl + "/verify?token=" + wt->token;
}

void WebLinkService::Revoke(WebLink::Type type, const NickCore *nc)
{
	if (!nc)
		return;

	const auto id = const_cast<NickCore *>(nc)->GetId();
	std::vector<WebToken *> old;
	for (const auto &[_, wt] : tokens)
	{
		if (wt->type == type && wt->account == id)
			old.push_back(wt);
	}
	for (auto *wt : old)
		delete wt;
}

WebToken *WebLinkService::Find(const Warden::string &token)
{
	auto it = tokens.find(token);
	if (it == tokens.end())
		return nullptr;

	auto *wt = it->second;
	if ((wt->expires && wt->expires <= Warden::CurTime) || !wt->GetNick() || !wt->IsPending())
	{
		delete wt;
		return nullptr;
	}
	return wt;
}

void WebLinkService::Expire()
{
	std::vector<WebToken *> old;
	for (const auto &[_, wt] : tokens)
	{
		if ((wt->expires && wt->expires <= Warden::CurTime) || !wt->GetNick() || !wt->IsPending())
			old.push_back(wt);
	}
	for (auto *wt : old)
		delete wt;
}

bool WebCPanel::Verify::OnRequest(HTTP::Provider *server, const Warden::string &page_name, HTTP::Client *client, HTTP::Message &message, HTTP::Reply &reply)
{
	TemplateFileServer::Replacements replacements;
	replacements["TITLE"] = page_title;

	const auto posted = !message.post_data.empty();
	if (posted && !WebPanel::IsAllowedOrigin(message))
	{
		reply.error = HTTP::BAD_REQUEST;
		reply.Write("Invalid request origin.");
		return true;
	}

	const auto token = WebPanel::GetRequestData(posted ? message.post_data : message.get_data, "token");
	auto *wt = token.empty() ? nullptr : WebLinkService::Find(token);
	auto serve = [&]() {
		TemplateFileServer page("verify.html");
		page.Serve(server, page_name, client, message, reply, replacements);
		return true;
	};

	if (!wt)
	{
		replacements["ERROR"] = "This link is invalid or has expired. Request a new one on IRC.";
		return serve();
	}

	auto *na = wt->GetNick();
	NickCore *nc = na->nc;
	replacements["NICK"] = na->nick;
	replacements["TOKEN"] = wt->token;

	switch (wt->type)
	{
		case WebLink::Type::REGISTER:
			replacements["HEADING"] = "Confirm your registration";
			replacements["ACTION"] = "Confirm the registration of " + na->nick + ".";
			break;
		case WebLink::Type::EMAIL:
			replacements["HEADING"] = "Confirm your email address";
			replacements["ACTION"] = "Confirm the new email address for " + nc->display + ".";
			break;
		case WebLink::Type::RESETPASS:
			replacements["HEADING"] = "Reset your password";
			replacements["ACTION"] = "Choose a new password for " + nc->display + ".";
			replacements["RESETPASS"] = "1";
			break;
	}

	// Opening the link only shows the Confirm button.
	if (!posted)
		return serve();

	std::vector<Warden::string> params;
	bool done = false;

	switch (wt->type)
	{
		case WebLink::Type::REGISTER:
		{
			if (!nc->HasExt("UNCONFIRMED"))
			{
				done = true;
				replacements["MESSAGES"] = "This account has already been confirmed.";
				break;
			}
			params.push_back(wt->code);
			WebPanel::RunCommand(client, na->nick, nc, "NickServ", "nickserv/confirm/register", params, replacements);
			done = !nc->HasExt("UNCONFIRMED");
			break;
		}
		case WebLink::Type::EMAIL:
		{
			const auto old_email = nc->email;
			params.push_back(wt->code);
			WebPanel::RunCommand(client, na->nick, nc, "NickServ", "nickserv/confirm/email", params, replacements);
			done = nc->email != old_email;
			break;
		}
		case WebLink::Type::RESETPASS:
		{
			if (nc->HasExt("NS_SUSPENDED"))
			{
				replacements["MESSAGES"] = Warden::Format(Language::Translate(NICK_X_SUSPENDED), na->nick.c_str());
				return serve();
			}

			const auto pass = WebPanel::GetRequestData(message.post_data, "password");
			if (pass.empty() || pass != WebPanel::GetRequestData(message.post_data, "password2"))
			{
				replacements["MESSAGES"] = "The passwords you entered do not match.";
				return serve();
			}

			// The token proves the request came from the account's email. The
			// new password ends the pending reset (ns_resetpass), and, as a
			// confirmed reset does, confirms an address-confirmed account.
			const auto old_pass = nc->pass;
			params.push_back(pass);
			WebPanel::RunCommand(client, na->nick, nc, "NickServ", "nickserv/set/password", params, replacements);
			done = nc->pass != old_pass;
			if (done)
			{
				if (Config->GetModule("ns_register").Get<const Warden::string>("registration").equals_ci("mail"))
					nc->Shrink<bool>("UNCONFIRMED");
				replacements["MESSAGES"] = "Your password has been changed. You can now identify with it on IRC.";
			}
			break;
		}
	}

	if (!done)
	{
		if (!replacements.count("MESSAGES"))
			replacements["MESSAGES"] = "The confirmation failed. Request a new link on IRC.";
		return serve();
	}

	Log(LOG_NORMAL, "webcpanel/verify") << "Confirmed " << TypeName(wt->type) << " for " << nc->display << " (" << na->nick << ") from " << client->GetIP();
	delete wt;

	replacements["DONE"] = "1";
	replacements.erase("TOKEN");
	return serve();
}
