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

#include "../webcpanel.h"

class WebpanelRequest final
	: public IdentifyRequest
{
	HTTP::Reply reply;
	HTTP::Message message;
	Reference<HTTP::Provider> server;
	Warden::string page_name;
	Reference<HTTP::Client> client;
	TemplateFileServer::Replacements replacements;

public:
	WebpanelRequest(Module *o, HTTP::Reply &r, HTTP::Message &m, HTTP::Provider *s, const Warden::string &p_n, HTTP::Client *c, TemplateFileServer::Replacements &re, const Warden::string &user, const Warden::string &pass)
		: IdentifyRequest(o, user, pass, c->GetIP())
		, reply(r)
		, message(m)
		, server(s)
		, page_name(p_n)
		, client(c)
		, replacements(re)
	{
	}

	void OnSuccess(NickAlias *na) override
	{
		if (!client || !server)
			return;

		if (na->nc->HasExt("NS_SUSPENDED"))
		{
			this->OnFail();
			return;
		}

		// Rate limit logins to 1/sec
		auto *last_login = na->nc->GetExt<time_t>("webcpanel_last_login");
		if (last_login != NULL && Warden::CurTime == *last_login)
		{
			this->OnFail();
			return;
		}

		Warden::string id;
		for (int i = 0; i < 64; ++i)
		{
			char c;
			do
				c = 48 + (Warden::RandomNumber() % 75);
			while (!isalnum(c));
			id += c;
		}

		na->Extend<Warden::string>("webcpanel_id", id);
		na->Extend<Warden::string>("webcpanel_ip", client->GetIP());
		na->nc->Extend<time_t>("webcpanel_last_login", Warden::CurTime);

		{
			HTTP::Reply::cookie c;
			c.emplace_back("account", na->nick);
			c.emplace_back("Path", "/");
			reply.cookies.push_back(c);
		}

		{
			HTTP::Reply::cookie c;
			c.emplace_back("id", id);
			c.emplace_back("Path", "/");
			reply.cookies.push_back(c);
		}

		reply.error = HTTP::FOUND;
		reply.headers["Location"] = Warden::string("http") + (server->IsSSL() ? "s" : "") + "://" + message.headers["Host"] + "/nickserv/info";

		client->SendReply(&reply);
	}

	void OnFail() override
	{
		if (!client || !server)
			return;
		replacements["INVALID_LOGIN"] = "Invalid username or password";
		TemplateFileServer page("login.html");
		page.Serve(server, page_name, client, message, reply, replacements);

		client->SendReply(&reply);
	}
};

bool WebCPanel::Index::OnRequest(HTTP::Provider *server, const Warden::string &page_name, HTTP::Client *client, HTTP::Message &message, HTTP::Reply &reply)
{
	if (!WebPanel::IsAllowedOrigin(message))
	{
		client->SendError(HTTP::BAD_REQUEST, "Invalid request origin.");
		return true;
	}

	TemplateFileServer::Replacements replacements;
	replacements["TITLE"] = page_title;

	const Warden::string user = WebPanel::GetRequestData(message.post_data, "username");
	const Warden::string pass = WebPanel::GetRequestData(message.post_data, "password");

	// Redirect if already logged in
	ServiceReference<Panel> panel("Panel", "webcpanel");
	auto *na = panel->GetNickFromSession(client, message);
	if (na)
	{
		reply.error = HTTP::FOUND;
		reply.headers["Location"] = Warden::string("http") + (server->IsSSL() ? "s" : "") + "://" + message.headers["Host"] + "/nickserv/info";

		client->SendReply(&reply);
		return false;
	}
	else if (!user.empty() && !pass.empty())
	{
		// Rate limit check.
		Warden::string ip = client->clientaddr.addr();

		auto it = last_login_attempt.find(ip);
		if (it != last_login_attempt.end())
		{
			time_t last_time = it->second;

			if (last_time == Warden::CurTime)
			{
				replacements["INVALID_LOGIN"] = "Rate limited";
				TemplateFileServer page("login.html");
				page.Serve(server, page_name, client, message, reply, replacements);
				return true;
			}
		}

		// don't let ip hash grow too long
		if (Warden::CurTime > last_clear + FLUSH_TIME)
		{
			last_login_attempt.clear();
			last_clear = Warden::CurTime;
		}

		last_login_attempt[ip] = Warden::CurTime;

		auto *req = new WebpanelRequest(me, reply, message, server, page_name, client, replacements, user, pass);
		FOREACH_MOD(OnCheckAuthentication, (NULL, req));
		req->Dispatch();
		return false;
	}

	TemplateFileServer page("login.html");
	page.Serve(server, page_name, client, message, reply, replacements);
	return true;
}
