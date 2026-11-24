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

#include "webcpanel.h"

Module *me;
Warden::string template_base, page_title;
std::vector<Warden::string> allowed_origins;

class ModuleWebCPanel final
	: public Module
{
	ServiceReference<HTTP::Provider> provider;
	Panel panel;
	PrimitiveExtensibleItem<Warden::string> id, ip;
	PrimitiveExtensibleItem<time_t> last_login;

	StaticFileServer style_css, logo_svg, cubes_png, favicon_ico, bootstrap_css, bootstrap_js, jquery_js;

	WebCPanel::Index index;
	WebCPanel::Logout logout;
	WebCPanel::Register _register;
	WebCPanel::Confirm confirm;
	WebCPanel::Verify verify;
	WebCPanel::WebTokenType webtokentype;
	WebCPanel::WebLinkService weblinkservice;

	WebCPanel::NickServ::Info nickserv_info;
	WebCPanel::NickServ::Cert nickserv_cert;
	WebCPanel::NickServ::Alist nickserv_alist;

	WebCPanel::ChanServ::Info chanserv_info;
	WebCPanel::ChanServ::Set chanserv_set;
	WebCPanel::ChanServ::Access chanserv_access;
	WebCPanel::ChanServ::Akick chanserv_akick;
	WebCPanel::ChanServ::Modes chanserv_modes;
	WebCPanel::ChanServ::Drop chanserv_drop;

	WebCPanel::MemoServ::Memos memoserv_memos;

	WebCPanel::HostServ::Request hostserv_request;

	WebCPanel::OperServ::Akill operserv_akill;


public:
	ModuleWebCPanel(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, EXTRA | VENDOR),
		provider(HTTP_PROVIDER),
		panel(this, "webcpanel"),
		id(this, "webcpanel_id"), ip(this, "webcpanel_ip"), last_login(this, "webcpanel_last_login"),
		style_css("style.css", "/static/style.css", "text/css"), logo_svg("logo.svg", "/static/logo.svg", "image/svg+xml"), cubes_png("cubes.png", "/static/cubes.png", "image/png"), favicon_ico("favicon.ico", "/favicon.ico", "image/x-icon"),
		bootstrap_css("bootstrap.min.css", "/static/bootstrap.min.css", "text/css"), bootstrap_js("bootstrap.min.js", "/static/bootstrap.min.js", "text/javascript"), jquery_js("jquery.min.js", "/static/jquery.min.js", "text/javascript"),
		index("/"), logout("/logout"), _register("/register"), confirm("/confirm"), verify("/verify"), weblinkservice(this),
		nickserv_info("NickServ", "/nickserv/info"), nickserv_cert("NickServ", "/nickserv/cert"), nickserv_alist("NickServ", "/nickserv/alist"),
		chanserv_info("ChanServ", "/chanserv/info"), chanserv_set("ChanServ", "/chanserv/set"), chanserv_access("ChanServ", "/chanserv/access"), chanserv_akick("ChanServ", "/chanserv/akick"),
		chanserv_modes("ChanServ", "/chanserv/modes"), chanserv_drop("ChanServ", "/chanserv/drop"), memoserv_memos("MemoServ", "/memoserv/memos"), hostserv_request("HostServ", "/hostserv/request"),
		operserv_akill("OperServ", "/operserv/akill")
	{

		me = this;

		const auto &block = Config->GetModule(this);
		template_base = Warden::ExpandData(block.Get<const Warden::string>("template_dir", "webcpanel/templates/default"));
		page_title = block.Get<const Warden::string>("title", "Warden IRC Services");
		spacesepstream(block.Get<const Warden::string>("allowed_origins")).GetTokens(allowed_origins);

		provider.SetServiceName(block.Get<const Warden::string>("server", "httpd/main"));
		if (!provider)
			throw ModuleException("Unable to find HTTPD provider. Is httpd loaded?");

		provider->RegisterPage(&this->style_css);
		provider->RegisterPage(&this->logo_svg);
		provider->RegisterPage(&this->bootstrap_css);
		provider->RegisterPage(&this->bootstrap_js);
		provider->RegisterPage(&this->jquery_js);
		provider->RegisterPage(&this->cubes_png);
		provider->RegisterPage(&this->favicon_ico);

		provider->RegisterPage(&this->index);
		provider->RegisterPage(&this->logout);
		provider->RegisterPage(&this->_register);
		provider->RegisterPage(&this->confirm);
		provider->RegisterPage(&this->verify);

		BotInfo *NickServ = Config->GetClient("NickServ");
		if (NickServ)
		{
			Section s;
			s.name = NickServ->nick;

			SubSection ss;
			ss.name = "Information";
			ss.url = "/nickserv/info";
			s.subsections.push_back(ss);
			provider->RegisterPage(&this->nickserv_info);

			if (IRCD && IRCD->CanCertFP)
			{
				ss.name = "SSL Certificates";
				ss.url = "/nickserv/cert";
				s.subsections.push_back(ss);
				provider->RegisterPage(&this->nickserv_cert);
			}

			ss.name = "AList";
			ss.url = "/nickserv/alist";
			s.subsections.push_back(ss);
			provider->RegisterPage(&this->nickserv_alist);

			panel.sections.push_back(s);
		}

		BotInfo *ChanServ = Config->GetClient("ChanServ");
		if (ChanServ)
		{
			Section s;
			s.name = ChanServ->nick;

			SubSection ss;
			ss.name = "Channels";
			ss.url = "/chanserv/info";
			s.subsections.push_back(ss);
			provider->RegisterPage(&this->chanserv_info);

			ss.name = "Settings";
			ss.url = "/chanserv/set";
			s.subsections.push_back(ss);
			provider->RegisterPage(&this->chanserv_set);

			ss.name = "Access";
			ss.url = "/chanserv/access";
			s.subsections.push_back(ss);
			provider->RegisterPage(&this->chanserv_access);

			ss.name = "Akick";
			ss.url = "/chanserv/akick";
			s.subsections.push_back(ss);
			provider->RegisterPage(&this->chanserv_akick);

			ss.name = "Modes";
			ss.url = "/chanserv/modes";
			s.subsections.push_back(ss);
			provider->RegisterPage(&this->chanserv_modes);

			ss.name = "Drop";
			ss.url = "/chanserv/drop";
			s.subsections.push_back(ss);
			provider->RegisterPage(&this->chanserv_drop);

			panel.sections.push_back(s);
		}

		BotInfo *MemoServ = Config->GetClient("MemoServ");
		if (MemoServ)
		{
			Section s;
			s.name = MemoServ->nick;

			SubSection ss;
			ss.name = "Memos";
			ss.url = "/memoserv/memos";
			s.subsections.push_back(ss);
			provider->RegisterPage(&this->memoserv_memos);

			panel.sections.push_back(s);
		}

		BotInfo *HostServ = Config->GetClient("HostServ");
		if (HostServ)
		{
			Section s;
			s.name = HostServ->nick;

			SubSection ss;
			ss.name = "VHost Request";
			ss.url = "/hostserv/request";
			s.subsections.push_back(ss);
			provider->RegisterPage(&this->hostserv_request);

			panel.sections.push_back(s);
		}

		BotInfo *OperServ = Config->GetClient("OperServ");
		if (OperServ)
		{
			Section s;
			s.name = OperServ->nick;

			SubSection ss;
			ss.name = "Akill";
			ss.url = "/operserv/akill";
			s.subsections.push_back(ss);
			provider->RegisterPage(&this->operserv_akill);

			panel.sections.push_back(s);
		}
	}

	~ModuleWebCPanel() override
	{
		if (provider)
		{
			provider->UnregisterPage(&this->style_css);
			provider->UnregisterPage(&this->logo_svg);
			provider->UnregisterPage(&this->bootstrap_css);
			provider->UnregisterPage(&this->bootstrap_js);
			provider->UnregisterPage(&this->jquery_js);
			provider->UnregisterPage(&this->cubes_png);
			provider->UnregisterPage(&this->favicon_ico);

			provider->UnregisterPage(&this->index);
			provider->UnregisterPage(&this->logout);
			provider->UnregisterPage(&this->_register);
			provider->UnregisterPage(&this->confirm);
			provider->UnregisterPage(&this->verify);

			provider->UnregisterPage(&this->nickserv_info);
			provider->UnregisterPage(&this->nickserv_cert);
			provider->UnregisterPage(&this->nickserv_alist);

			provider->UnregisterPage(&this->chanserv_info);
			provider->UnregisterPage(&this->chanserv_set);
			provider->UnregisterPage(&this->chanserv_access);
			provider->UnregisterPage(&this->chanserv_akick);
			provider->UnregisterPage(&this->chanserv_modes);
			provider->UnregisterPage(&this->chanserv_drop);

			provider->UnregisterPage(&this->memoserv_memos);

			provider->UnregisterPage(&this->hostserv_request);

			provider->UnregisterPage(&this->operserv_akill);
		}
	}

	void OnPasswordChange(CommandSource &source, NickCore *nc) override
	{
		// A new password logs the account out of the web panel everywhere.
		for (auto *na : *nc->aliases)
		{
			id.Unset(na);
			ip.Unset(na);
		}
	}

	void OnExpireTick() override
	{
		WebCPanel::WebLinkService::Expire();
	}
};

namespace WebPanel
{
	bool CheckParams(const std::vector<Warden::string> &params)
	{
		static Warden::string invalid("\r\n\0", 3);
		for (std::vector<Warden::string>::const_iterator it = params.begin(); it != params.end(); ++it)
		{
			if (it->length() > 512 || it->find_first_of(invalid) != Warden::string::npos)
				return false;
		}
		return true;
	}

	Warden::string GetRequestData(const std::map<Warden::string, Warden::string, ci::less> &data, const Warden::string &key)
	{
		const auto dit = data.find(key);
		if (dit == data.end() || dit->second.length() > 512)
			return ""; // No data or too long.

		return Warden::ReplaceUnsafe(dit->second);
	}

	// The host part of an Origin or Host value: no scheme, path or port.
	static Warden::string HostOf(Warden::string value)
	{
		auto pos = value.find("://");
		if (pos != Warden::string::npos)
			value = value.substr(pos + 3);
		pos = value.find('/');
		if (pos != Warden::string::npos)
			value = value.substr(0, pos);
		pos = value.rfind(':');
		if (pos != Warden::string::npos && value.find(']', pos) == Warden::string::npos)
			value = value.substr(0, pos);
		return value.trim();
	}

	bool IsAllowedOrigin(const HTTP::Message &message)
	{
		auto it = message.headers.find("Origin");
		if (it == message.headers.end())
			return true; // Browsers send Origin with every cross-site POST.

		if (!allowed_origins.empty())
		{
			for (const auto &allowed_origin : allowed_origins)
			{
				if (Warden::Match(it->second, allowed_origin))
					return true;
			}
			return false;
		}

		// Without allowed_origins, only the panel's own pages may post to it:
		// the Origin must name the host the request was sent to (Host, or
		// X-Forwarded-Host behind a proxy that rewrites Host).
		const auto origin = HostOf(it->second);
		if (origin.empty())
			return false;
		for (const auto *header : { "Host", "X-Forwarded-Host" })
		{
			auto hit = message.headers.find(header);
			if (hit != message.headers.end() && origin.equals_ci(HostOf(hit->second)))
				return true;
		}
		return false;
	}

	void RunCommand(HTTP::Client *client, const Warden::string &user, NickCore *nc, const Warden::string &service, const Warden::string &c, std::vector<Warden::string> &params, TemplateFileServer::Replacements &r, const Warden::string &key)
	{
		ServiceReference<Command> cmd("Command", c);
		if (!cmd)
		{
			r[key] = "Unable to find command " + c;
			return;
		}

		if (!CheckParams(params))
		{
			r[key] = "Unsafe characters found in input";
			return;
		}

		if (params.size() < cmd->min_params)
			return;

		BotInfo *bi = Config->GetClient(service);
		if (!bi)
		{
			if (BotListByNick->empty())
				return;
			bi = BotListByNick->begin()->second; // Pick one...
		}

		struct MyComandReply final
			: CommandReply
		{
			TemplateFileServer::Replacements &re;
			const Warden::string &k;

			MyComandReply(TemplateFileServer::Replacements &_r, const Warden::string &_k) : re(_r), k(_k) { }

			void SendMessage(BotInfo *source, const Warden::string &msg) override
			{
				re[k] = msg.replace_all_cs("\x1B", "\x20");
			}
		}
		my_reply(r, key);

		CommandSource source(user, NULL, nc, &my_reply, bi);
		source.ip = client->GetIP();

		CommandInfo info;
		info.name = c;

		cmd->Run(source, "", info, params);
	}

	void RunCommandWithName(HTTP::Client *client, NickCore *nc, const Warden::string &service, const Warden::string &c, const Warden::string &cmdname, std::vector<Warden::string> &params, TemplateFileServer::Replacements &r, const Warden::string &key)
	{
		ServiceReference<Command> cmd("Command", c);
		if (!cmd)
		{
			r[key] = "Unable to find command " + c;
			return;
		}

		if (!CheckParams(params))
		{
			r[key] = "Unsafe characters found in input";
			return;
		}

		BotInfo *bi = Config->GetClient(service);
		if (!bi)
			return;

		CommandInfo *info = bi->GetCommand(cmdname);
		if (!info)
			return;

		struct MyComandReply final
			: CommandReply
		{
			TemplateFileServer::Replacements &re;
			const Warden::string &k;

			MyComandReply(TemplateFileServer::Replacements &_r, const Warden::string &_k) : re(_r), k(_k) { }

			void SendMessage(BotInfo *source, const Warden::string &msg) override
			{
				re[k] = msg.replace_all_cs("\x1B", "\x20");
			}
		}
		my_reply(r, key);

		CommandSource source(nc->display, NULL, nc, &my_reply, bi);
		source.ip = client->GetIP();

		cmd->Run(source, cmdname, *info, params);
	}
}

MODULE_INIT(ModuleWebCPanel)
