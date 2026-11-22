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
#include "modules/httpd.h"
#include "modules/ssl.h"

static Warden::string BuildDate()
{
	char timebuf[64];
	struct tm *tm = localtime(&Warden::CurTime);
	strftime(timebuf, sizeof(timebuf), "%a, %d %b %Y %H:%M:%S %Z", tm);
	return timebuf;
}

static Warden::string GetStatusFromCode(HTTP::Error err)
{
	switch (err)
	{
		case HTTP::OK:
			return "200 OK";
		case HTTP::FOUND:
			return "302 Found";
		case HTTP::BAD_REQUEST:
			return "400 Bad Request";
		case HTTP::PAGE_NOT_FOUND:
			return "404 Not Found";
		case HTTP::NOT_SUPPORTED:
			return "505 HTTP Version Not Supported";
	}

	return "501 Not Implemented";
}

class MyHTTPClient final
	: public HTTP::Client
{
	HTTP::Provider *provider;
	HTTP::Message message;
	bool header_done = false, served = false;
	Warden::string page_name;
	Reference<HTTP::Page> page;
	Warden::string ip;

	unsigned content_length = 0;

	enum
	{
		ACTION_NONE,
		ACTION_GET,
		ACTION_POST
	} action = ACTION_NONE;

	void Serve()
	{
		if (this->served)
			return;
		this->served = true;

		if (!this->page)
		{
			this->SendError(HTTP::PAGE_NOT_FOUND, "Page not found");
			return;
		}

		if (std::find(this->provider->ext_ips.begin(), this->provider->ext_ips.end(), this->ip) != this->provider->ext_ips.end())
		{
			for (auto &token : this->provider->ext_headers)
			{
				if (this->message.headers.count(token))
				{
					this->ip = this->message.headers[token];
					Log(LOG_DEBUG, "httpd") << "httpd: IP for connection " << this->GetFD() << " changed to " << this->ip;
					break;
				}
			}
		}

		Log(LOG_DEBUG, "httpd") << "httpd: Serving page " << this->page_name << " to " << this->ip;

		HTTP::Reply reply;
		reply.content_type = this->page->GetContentType();

		if (this->page->OnRequest(this->provider, this->page_name, this, this->message, reply))
			this->SendReply(&reply);
	}

public:
	time_t created;

	MyHTTPClient(HTTP::Provider *l, int f, const sockaddrs &a) : Socket(f, l->GetFamily()), HTTP::Client(l, f, a), provider(l), ip(a.addr()), created(Warden::CurTime)
	{
		Log(LOG_DEBUG, "httpd") << "Accepted connection " << f << " from " << a.addr();
	}

	~MyHTTPClient() override
	{
		Log(LOG_DEBUG, "httpd") << "Closing connection " << this->GetFD() << " from " << this->ip;
	}

	/* Close connection once all data is written */
	bool ProcessWrite() override
	{
		return !(!BinarySocket::ProcessWrite() || this->write_buffer.empty());
	}

	Warden::string GetIP() const override
	{
		return this->ip;
	}

	bool Read(const char *buffer, size_t l) override
	{
		message.content.append(buffer, l);

		for (size_t nl; !this->header_done && (nl = message.content.find('\n')) != Warden::string::npos;)
		{
			Warden::string token = message.content.substr(0, nl).trim();
			message.content = message.content.substr(nl + 1);

			if (token.empty())
				this->header_done = true;
			else
				this->Read(token);
		}

		if (!this->header_done)
			return true;

		if (this->message.content.length() >= this->content_length)
		{
			sepstream sep(this->message.content, '&');
			Warden::string token;

			while (sep.GetToken(token))
			{
				size_t sz = token.find('=');
				if (sz == Warden::string::npos || !sz || sz + 1 >= token.length())
					continue;
				this->message.post_data[token.substr(0, sz)] = HTTP::URLDecode(token.substr(sz + 1));
				Log(LOG_DEBUG_2) << "HTTP POST from " << this->clientaddr.addr() << ": " << token.substr(0, sz) << ": " << this->message.post_data[token.substr(0, sz)];
			}

			this->Serve();
		}

		return true;
	}

	bool Read(const Warden::string &buf)
	{
		Log(LOG_DEBUG_2) << "HTTP from " << this->clientaddr.addr() << ": " << buf;

		if (this->action == ACTION_NONE)
		{
			std::vector<Warden::string> params;
			spacesepstream(buf).GetTokens(params);

			if (params.empty() || (params[0] != "GET" && params[0] != "POST"))
			{
				this->SendError(HTTP::BAD_REQUEST, "Unknown operation");
				return true;
			}

			if (params.size() != 3)
			{
				this->SendError(HTTP::BAD_REQUEST, "Invalid parameters");
				return true;
			}

			if (params[0] == "GET")
				this->action = ACTION_GET;
			else if (params[0] == "POST")
				this->action = ACTION_POST;

			Warden::string targ = params[1];
			size_t q = targ.find('?');
			if (q != Warden::string::npos)
			{
				sepstream sep(targ.substr(q + 1), '&');
				targ = targ.substr(0, q);

				Warden::string token;
				while (sep.GetToken(token))
				{
					size_t sz = token.find('=');
					if (sz == Warden::string::npos || !sz || sz + 1 >= token.length())
						continue;
					this->message.get_data[token.substr(0, sz)] = HTTP::URLDecode(token.substr(sz + 1));
				}
			}

			this->page = this->provider->FindPage(targ);
			this->page_name = targ;
		}
		else if (buf.find_ci("Cookie: ") == 0)
		{
			spacesepstream sep(buf.substr(8));
			Warden::string token;

			while (sep.GetToken(token))
			{
				size_t sz = token.find('=');
				if (sz == Warden::string::npos || !sz || sz + 1 >= token.length())
					continue;
				size_t end = token.length() - (sz + 1);
				if (!sep.StreamEnd())
					--end; // Remove trailing ;
				this->message.cookies[token.substr(0, sz)] = token.substr(sz + 1, end);
			}
		}
		else if (buf.find_ci("Content-Length: ") == 0)
		{
			if (auto len = Warden::TryConvert<unsigned>(buf.substr(16)))
				this->content_length = len.value();
		}
		else if (buf.find(':') != Warden::string::npos)
		{
			size_t sz = buf.find(':');
			if (sz + 2 < buf.length())
				this->message.headers[buf.substr(0, sz)] = buf.substr(sz + 2);
		}

		return true;
	}

	void SendError(HTTP::Error err, const Warden::string &msg) override
	{
		HTTP::Reply h;

		h.error = err;

		h.Write(msg);

		this->SendReply(&h);
	}

	void SendReply(HTTP::Reply *msg) override
	{
		this->WriteClient("HTTP/1.1 " + GetStatusFromCode(msg->error));
		this->WriteClient("Date: " + BuildDate());
		this->WriteClient("Server: Warden-" + Warden::VersionShort());
		if (msg->content_type.empty())
			this->WriteClient("Content-Type: text/html");
		else
			this->WriteClient("Content-Type: " + msg->content_type);
		this->WriteClient("Content-Length: " + Warden::ToString(msg->length));

		for (const auto &cookie : msg->cookies)
		{
			Warden::string buf = "Set-Cookie:";

			for (const auto &[name, value] : cookie)
				buf += " " + name + "=" + value + ";";

			buf += " HttpOnly; SameSite=Strict";

			this->WriteClient(buf);
		}

		for (auto &[name, value] : msg->headers)
			this->WriteClient(name + ": " + value);

		this->WriteClient("Connection: Close");
		this->WriteClient("");

		for (auto *d : msg->out)
		{
				this->Write(d->buf, d->len);

			delete d;
		}

		msg->out.clear();
	}
};

class MyHTTPProvider final
	: public HTTP::Provider
	, public Timer
{
	int timeout;
	std::map<Warden::string, HTTP::Page *> pages;
	std::list<Reference<MyHTTPClient> > clients;

public:
	MyHTTPProvider(Module *c, const Warden::string &n, const Warden::string &i, const unsigned short p, const int t, bool s)
		: Socket(-1, i.find(':') == Warden::string::npos ? AF_INET : AF_INET6)
		, HTTP::Provider(c, n, i, p, s)
		, Timer(c, 10)
		, timeout(t)
	{
	}

	bool Tick() override
	{
		while (!this->clients.empty())
		{
			Reference<MyHTTPClient>& c = this->clients.front();
			if (c && c->created + this->timeout >= Warden::CurTime)
				break;

			delete c;
			this->clients.pop_front();
		}
		return true;
	}

	ClientSocket *OnAccept(int fd, const sockaddrs &addr) override
	{
		auto *c = new MyHTTPClient(this, fd, addr);
		this->clients.emplace_back(c);
		return c;
	}

	bool RegisterPage(HTTP::Page *page) override
	{
		return this->pages.emplace(page->GetURL(), page).second;
	}

	void UnregisterPage(HTTP::Page *page) override
	{
		this->pages.erase(page->GetURL());
	}

	HTTP::Page *FindPage(const Warden::string &pname) override
	{
		if (this->pages.count(pname) == 0)
			return NULL;
		return this->pages[pname];
	}
};

class HTTPD final
	: public Module
{
	ServiceReference<SSLService> sslref;
	std::map<Warden::string, MyHTTPProvider *> providers;
public:
	HTTPD(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, EXTRA | VENDOR), sslref("SSLService", "ssl")
	{

	}

	~HTTPD() override
	{
		for (auto it = SocketEngine::Sockets.begin(), it_end = SocketEngine::Sockets.end(); it != it_end;)
		{
			Socket *s = it->second;
			++it;

			if (dynamic_cast<MyHTTPProvider *>(s) || dynamic_cast<MyHTTPClient *>(s))
				delete s;
		}

		this->providers.clear();
	}

	void OnReload(Configuration::Conf &config) override
	{
		const auto &conf = config.GetModule(this);
		std::set<Warden::string> existing;

		for (const auto &[_, block] : conf.GetBlocks("httpd"))
		{
			const Warden::string &hname = block.Get<const Warden::string>("name", "httpd/main");
			existing.insert(hname);

			Warden::string ip = block.Get<const Warden::string>("ip");
			int port = block.Get<int>("port", "8080");
			int timeout = block.Get<int>("timeout", "30");
			bool ssl = block.Get<bool>("ssl", "no");
			Warden::string ext_ip = block.Get<const Warden::string>("extforward_ip");
			Warden::string ext_header = block.Get<const Warden::string>("extforward_header");

			if (ip.empty())
			{
				Log(this) << "You must configure a bind IP for HTTP server " << hname;
				continue;
			}
			else if (port <= 0 || port > 65535)
			{
				Log(this) << "You must configure a (valid) listen port for HTTP server " << hname;
				continue;
			}

			MyHTTPProvider *p;
			if (this->providers.count(hname) == 0)
			{
				try
				{
					p = new MyHTTPProvider(this, hname, ip, port, timeout, ssl);
					if (ssl && sslref)
						sslref->Init(p);
				}
				catch (const SocketException &ex)
				{
					Log(this) << "Unable to create HTTP server " << hname << ": " << ex.GetReason();
					continue;
				}
				this->providers[hname] = p;

				Log(this) << "Created HTTP server " << hname;
			}
			else
			{
				p = this->providers[hname];

				if (p->GetIP() != ip || p->GetPort() != port)
				{
					delete p;
					this->providers.erase(hname);

					Log(this) << "Changing HTTP server " << hname << " to " << ip << ":" << port;

					try
					{
						p = new MyHTTPProvider(this, hname, ip, port, timeout, ssl);
						if (ssl && sslref)
							sslref->Init(p);
					}
					catch (const SocketException &ex)
					{
						Log(this) << "Unable to create HTTP server " << hname << ": " << ex.GetReason();
						continue;
					}

					this->providers[hname] = p;
				}
			}


			spacesepstream(ext_ip).GetTokens(p->ext_ips);
			spacesepstream(ext_header).GetTokens(p->ext_headers);
		}

		for (auto it = this->providers.begin(), it_end = this->providers.end(); it != it_end;)
		{
			HTTP::Provider *p = it->second;
			++it;

			if (existing.count(p->name) == 0)
			{
				Log(this) << "Removing HTTP server " << p->name;
				this->providers.erase(p->name);
				delete p;
			}
		}
	}

	void OnModuleLoad(User *u, Module *m) override
	{
		for (auto &[_, p] : this->providers)
		{
			if (p->IsSSL() && sslref)
				try
				{
					sslref->Init(p);
				}
				catch (const CoreException &) { } // Throws on reinitialization
		}
	}
};

MODULE_INIT(HTTPD)
