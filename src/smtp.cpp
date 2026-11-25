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

// A small SMTP client so mail can go straight to a mail server instead of
// through sendmail. One connection per mail; temporary failures are retried
// in memory after 1, 5 and 15 minutes.

#include "warden.h"
#include "services.h"
#include "mail.h"
#include "config.h"
#include "sockets.h"
#include "timers.h"
#include "textproc.h"
#include "modules/ssl.h"

namespace
{
	const time_t retry_delays[] = { 60, 5 * 60, 15 * 60 };
	const time_t connect_timeout = 60;

	struct SMTPSettings final
	{
		Warden::string server;
		int port;
		Warden::string tls; // none, starttls or tls
		Warden::string username;
		Warden::string password;
		bool verify;
		Warden::string helo;

		static SMTPSettings Load(const Configuration::Conf &conf)
		{
			const auto &b = conf.GetBlock("mail");
			SMTPSettings s;
			s.server = b.Get<const Warden::string>("smtpserver");
			s.tls = b.Get<const Warden::string>("smtptls", "starttls").lower();
			s.port = b.Get<int>("smtpport", s.tls == "none" ? "25" : (s.tls == "tls" ? "465" : "587"));
			s.username = b.Get<const Warden::string>("smtpusername");
			s.password = b.Get<const Warden::string>("smtppassword");
			s.verify = b.Get<bool>("smtpverify", "yes");
			s.helo = conf.GetBlock("serverinfo").Get<const Warden::string>("name", "localhost");
			return s;
		}

		bool IsLocal() const
		{
			return server.equals_ci("localhost") || server == "127.0.0.1" || server == "::1";
		}
	};

	/* Returns the address part of "Name <address>", or the whole string. */
	Warden::string BareAddress(const Warden::string &from)
	{
		auto lt = from.rfind('<');
		auto gt = from.rfind('>');
		if (lt != Warden::string::npos && gt != Warden::string::npos && gt > lt)
			return from.substr(lt + 1, gt - lt - 1);
		return from;
	}

	struct SMTPMail final
	{
		Warden::string mail_to;
		Warden::string addr;
		Warden::string envelope_from;
		Warden::string data; // headers and body, CRLF line ends, dot-stuffed
		unsigned attempt = 0;
	};

	void Attempt(SMTPMail *mail);

	class SMTPRetryTimer final
		: public Timer
	{
		SMTPMail *mail;

	public:
		SMTPRetryTimer(SMTPMail *m, time_t delay) : Timer(delay), mail(m) { }

		bool Tick() override
		{
			Attempt(this->mail);
			return false;
		}
	};

	/* Logs a mail that is done with, one way or the other, and frees it. */
	void Finish(SMTPMail *mail, const Warden::string &error, bool temporary)
	{
		if (error.empty())
		{
			Log(LOG_NORMAL, "mail") << "Successfully delivered mail for " << mail->mail_to << " (" << mail->addr << ")";
		}
		else if (temporary && mail->attempt < std::size(retry_delays))
		{
			const auto delay = retry_delays[mail->attempt++];
			Log(LOG_NORMAL, "mail") << "Unable to deliver mail for " << mail->mail_to << " (" << mail->addr << "), retrying in " << Warden::Duration(delay) << ": " << error;
			new SMTPRetryTimer(mail, delay);
			return;
		}
		else
		{
			Log(LOG_NORMAL, "mail") << "Error delivering mail for " << mail->mail_to << " (" << mail->addr << "): " << error;
		}
		delete mail;
	}

	class SMTPSocket;

	class SMTPTimeout final
		: public Timer
	{
		SMTPSocket *sock;

	public:
		SMTPTimeout(SMTPSocket *s) : Timer(connect_timeout), sock(s) { }
		bool Tick() override;
	};

	class SMTPSocket final
		: public ConnectionSocket
		, public BufferedSocket
	{
		enum class State
		{
			GREETING,
			EHLO,
			STARTTLS,
			HANDSHAKE,
			AUTH_PLAIN,
			AUTH_LOGIN_USER,
			AUTH_LOGIN_PASS,
			AUTH_LOGIN_DONE,
			MAIL_FROM,
			RCPT_TO,
			DATA,
			BODY,
			QUIT,
		};

		SMTPSettings settings;
		SMTPMail *mail;
		State state = State::GREETING;
		bool secure;
		std::vector<Warden::string> reply;
		Warden::string capabilities;

		void Send(const Warden::string &line, State next)
		{
			this->Write(line);
			this->state = next;
		}

		/* Ends this mail's attempt. The socket closes either way. */
		void Done(const Warden::string &error, bool temporary)
		{
			if (this->mail)
			{
				Finish(this->mail, error, temporary);
				this->mail = nullptr;
			}

			if (error.empty() && this->state != State::QUIT)
				this->Send("QUIT", State::QUIT);
			else
				this->flags[SF_DEAD] = true;
		}

		/* Fails with the server's reply; 4xx is temporary, anything else is not. */
		void Reject(const Warden::string &what)
		{
			Warden::string text;
			for (const auto &line : this->reply)
				text += (text.empty() ? "" : " / ") + line;
			const auto temporary = !text.empty() && text[0] == '4';
			this->Done("the server rejected " + what + ": " + text, temporary);
		}

		bool HasCapability(const Warden::string &cap) const
		{
			spacesepstream sep(this->capabilities);
			for (Warden::string token; sep.GetToken(token); )
				if (token.equals_ci(cap))
					return true;
			return false;
		}

		void StartAuth()
		{
			if (this->settings.username.empty())
			{
				this->SendMailFrom();
				return;
			}

			if (!this->secure && !this->settings.IsLocal())
			{
				this->Done("refusing to send the SMTP password without TLS", false);
				return;
			}

			if (this->HasCapability("PLAIN"))
			{
				Warden::string creds;
				creds.push_back('\0');
				creds += this->settings.username;
				creds.push_back('\0');
				creds += this->settings.password;
				this->Send("AUTH PLAIN " + Warden::B64Encode(creds), State::AUTH_PLAIN);
			}
			else if (this->HasCapability("LOGIN"))
				this->Send("AUTH LOGIN", State::AUTH_LOGIN_USER);
			else
				this->Done("the server offers no login method Warden supports (PLAIN or LOGIN)", false);
		}

		void SendMailFrom()
		{
			this->Send("MAIL FROM:<" + this->mail->envelope_from + ">", State::MAIL_FROM);
		}

		void OnReply(int code)
		{
			switch (this->state)
			{
				case State::GREETING:
					if (code != 220)
						return this->Reject("the connection");
					this->Send("EHLO " + this->settings.helo, State::EHLO);
					break;

				case State::EHLO:
					if (code != 250)
						return this->Reject("EHLO");
					this->capabilities.clear();
					for (size_t i = 1; i < this->reply.size(); ++i)
						this->capabilities += " " + this->reply[i].substr(4);

					if (this->settings.tls == "starttls" && !this->secure)
					{
						if (!this->HasCapability("STARTTLS"))
							return this->Done("the server does not offer STARTTLS (set mail:smtptls to \"tls\" or \"none\")", false);
						this->Send("STARTTLS", State::STARTTLS);
					}
					else
						this->StartAuth();
					break;

				case State::STARTTLS:
				{
					if (code != 220)
						return this->Reject("STARTTLS");

					ServiceReference<SSLService> ssl("SSLService", "ssl");
					if (!ssl)
						return this->Done("no SSL module (ssl_openssl or ssl_gnutls) is loaded", true);

					// Switch this connection to TLS; the handshake runs through the
					// socket engine and calls OnConnect again when it is done.
					this->state = State::HANDSHAKE;
					this->secure = true;
					ssl->Init(this, this->settings.server, this->settings.verify);
					this->flags[SF_CONNECTED] = false;
					this->flags[SF_CONNECTING] = true;
					this->flags[this->io->FinishConnect(this)] = true;
					break;
				}

				case State::AUTH_PLAIN:
				case State::AUTH_LOGIN_DONE:
					if (code != 235)
						return this->Reject("the SMTP username or password");
					this->SendMailFrom();
					break;

				case State::AUTH_LOGIN_USER:
					if (code != 334)
						return this->Reject("AUTH LOGIN");
					this->Send(Warden::B64Encode(this->settings.username), State::AUTH_LOGIN_PASS);
					break;

				case State::AUTH_LOGIN_PASS:
					if (code != 334)
						return this->Reject("the SMTP username");
					this->Send(Warden::B64Encode(this->settings.password), State::AUTH_LOGIN_DONE);
					break;

				case State::MAIL_FROM:
					if (code != 250)
						return this->Reject("the sender " + this->mail->envelope_from);
					this->Send("RCPT TO:<" + this->mail->addr + ">", State::RCPT_TO);
					break;

				case State::RCPT_TO:
					if (code != 250 && code != 251)
						return this->Reject("the recipient");
					this->Send("DATA", State::DATA);
					break;

				case State::DATA:
					if (code != 354)
						return this->Reject("DATA");
					// Write() ends each call with CRLF, and data already ends with one.
					this->Write(this->mail->data.substr(0, this->mail->data.length() - 2));
					this->Send(".", State::BODY);
					break;

				case State::BODY:
					if (code != 250)
						return this->Reject("the message");
					this->Done("", false);
					break;

				case State::HANDSHAKE:
					break;

				case State::QUIT:
					this->flags[SF_DEAD] = true;
					break;
			}
		}

	public:
		SMTPTimeout *timeout;

		SMTPSocket(const SMTPSettings &s, SMTPMail *m, int family)
			: Socket(-1, family)
			, settings(s)
			, mail(m)
			, secure(s.tls == "tls")
			, timeout(new SMTPTimeout(this))
		{
		}

		~SMTPSocket() override
		{
			delete this->timeout;
			if (this->mail)
				Finish(this->mail, "the connection was closed", true);
		}

		void Fail(const Warden::string &error)
		{
			this->Done(error, true);
		}

		void OnConnect() override
		{
			if (this->state == State::HANDSHAKE)
				this->Send("EHLO " + this->settings.helo, State::EHLO);
		}

		void OnError(const Warden::string &error) override
		{
			Warden::string why = error.empty() ? "the connection was closed" : error;
			if (!this->flags[SF_CONNECTED] && this->state == State::GREETING)
				why = "unable to connect to " + this->settings.server + ":" + Warden::ToString(this->settings.port) + ": " + why;
			if (this->mail)
			{
				Finish(this->mail, why, true);
				this->mail = nullptr;
			}
		}

		bool ProcessRead() override
		{
			bool ok = BufferedSocket::ProcessRead();
			for (Warden::string line; !(line = this->GetLine()).empty(); )
			{
				Log(LOG_DEBUG_2) << "SMTP: " << line;
				if (this->state == State::HANDSHAKE)
					continue; // nothing should arrive between STARTTLS and the handshake

				this->reply.push_back(line);
				if (line.length() > 3 && line[3] == '-')
					continue; // more lines of this reply follow

				auto code = Warden::TryConvert<int>(line.substr(0, 3)).value_or(0);
				this->OnReply(code);
				this->reply.clear();
				if (this->flags[SF_DEAD])
					break;
			}
			return ok;
		}
	};

	bool SMTPTimeout::Tick()
	{
		this->sock->timeout = nullptr;
		this->sock->Fail("the server did not answer in time");
		this->sock->flags[SF_DEAD] = true;
		return false;
	}

	void Attempt(SMTPMail *mail)
	{
		const auto settings = SMTPSettings::Load(*Config);
		if (settings.server.empty())
		{
			Finish(mail, "mail:smtpserver is no longer set", false);
			return;
		}

		// The same checks as at startup; after a bad reload they fail each mail.
		const auto error = Mail::CheckSMTPConfig(*Config);
		if (!error.empty())
		{
			Finish(mail, error, true);
			return;
		}

		ServiceReference<SSLService> ssl("SSLService", "ssl");

		const auto ip = Warden::Resolve(settings.server, AF_UNSPEC);
		SMTPSocket *sock = nullptr;
		try
		{
			sock = new SMTPSocket(settings, mail, ip.find(':') != Warden::string::npos ? AF_INET6 : AF_INET);
			if (settings.tls == "tls")
				ssl->Init(sock, settings.server, settings.verify);
			sock->Connect(ip, settings.port);
		}
		catch (const SocketException &ex)
		{
			if (sock)
			{
				sock->Fail("unable to connect to " + settings.server + ": " + ex.GetReason());
				sock->flags[SF_DEAD] = true;
			}
			else
				Finish(mail, "unable to connect to " + settings.server + ": " + ex.GetReason(), true);
		}
	}

	/* The current date in RFC 5322 format. */
	Warden::string MailDate()
	{
		char buf[64];
		tm tm = *localtime(&Warden::CurTime);
		strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S %z", &tm);
		return buf;
	}
}

bool Mail::UseSMTP()
{
	return !Config->GetBlock("mail").Get<const Warden::string>("smtpserver").empty();
}

void Mail::SendSMTP(const Warden::string &send_from, const Warden::string &mail_to, const Warden::string &addr, const Warden::string &subject, const Warden::string &message, HeaderMap headers)
{
	const auto envelope = BareAddress(send_from);
	const auto at = envelope.find('@');
	const auto domain = at == Warden::string::npos ? Config->GetBlock("serverinfo").Get<const Warden::string>("name") : envelope.substr(at + 1);

	headers.emplace("MIME-Version", "1.0");
	headers.emplace("Content-Transfer-Encoding", "8bit");
	headers.emplace("Content-Type", "text/plain; charset=UTF-8");
	headers.emplace("Date", MailDate());
	headers.emplace("Message-ID", "<" + Warden::ToString(Warden::CurTime) + "." + Warden::Random(16) + "@" + domain + ">");

	Warden::string data = "From: " + send_from + "\r\n";
	if (Config->GetBlock("mail").Get<bool>("dontquoteaddresses"))
		data += "To: " + mail_to + " <" + addr + ">\r\n";
	else
		data += "To: \"" + mail_to.replace_all_cs("\\", "\\\\").replace_all_cs("\"", "\\\"") + "\" <" + addr + ">\r\n";
	data += "Subject: " + subject + "\r\n";
	for (const auto &[hname, hvalue] : headers)
		data += hname + ": " + hvalue + "\r\n";
	data += "\r\n";

	std::stringstream stream(message.str());
	for (Warden::string line; std::getline(stream, line.str()); )
	{
		line.trim("\r");
		if (!line.empty() && line[0] == '.')
			data += "."; // dot-stuffing, RFC 5321 4.5.2
		data += line + "\r\n";
	}

	auto *mail = new SMTPMail();
	mail->mail_to = mail_to;
	mail->addr = addr;
	mail->envelope_from = envelope;
	mail->data = data;
	Attempt(mail);
}

// Checks an address setting is "addr@domain" or "Name <addr@domain>".
static Warden::string CheckAddress(const Configuration::Conf &conf, const char *key)
{
	const auto value = conf.GetBlock("mail").Get<const Warden::string>(key);
	if (value.empty())
		return "";

	auto addr = value;
	const auto lt = value.find('<');
	if (lt != Warden::string::npos)
	{
		if (value.find('>') != value.length() - 1 || value.find('<', lt + 1) != Warden::string::npos)
			return Warden::string("mail:") + key + " is not a valid address: \"" + value + "\" (use \"Name <user@example.com>\" or \"user@example.com\")";
		addr = value.substr(lt + 1, value.length() - lt - 2);
	}

	const auto at = addr.find('@');
	if (at == 0 || at == Warden::string::npos || at == addr.length() - 1 || addr.find('@', at + 1) != Warden::string::npos
		|| addr.find_first_of(" \t\r\n<>\"") != Warden::string::npos)
		return Warden::string("mail:") + key + " is not a valid address: \"" + value + "\" (use \"Name <user@example.com>\" or \"user@example.com\")";
	return "";
}

Warden::string Mail::CheckSMTPConfig(const Configuration::Conf &conf)
{
	if (!conf.GetBlock("mail").Get<bool>("usemail"))
		return "";

	for (const auto *key : { "sendfrom", "replyto" })
	{
		const auto err = CheckAddress(conf, key);
		if (!err.empty())
			return err;
	}

	const auto settings = SMTPSettings::Load(conf);
	if (settings.server.empty())
		return "";

	if (settings.tls != "none" && settings.tls != "starttls" && settings.tls != "tls")
		return "mail:smtptls must be \"none\", \"starttls\" or \"tls\", not \"" + settings.tls + "\"";

	if (settings.tls != "none" && !ServiceReference<SSLService>("SSLService", "ssl"))
		return "mail:smtptls is \"" + settings.tls + "\" but no SSL module (ssl_openssl or ssl_gnutls) is loaded";

	if (settings.tls == "none" && !settings.username.empty() && !settings.IsLocal())
		return "mail:smtpusername is set but mail:smtptls is \"none\", so the password would be sent unencrypted to " + settings.server;

	return "";
}

void Mail::WarnSMTPConfig(const Configuration::Conf &conf)
{
	const auto settings = SMTPSettings::Load(conf);
	if (settings.server.empty() || !conf.GetBlock("mail").Get<bool>("usemail"))
		return;

	if (settings.tls != "none" && !settings.verify)
		Log() << "Warning: mail:smtpverify is off, so the certificate of " << settings.server << " is not checked. Anyone who can intercept the connection can read the SMTP password and the mail.";
}
