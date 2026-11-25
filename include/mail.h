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

#pragma once

#include "warden.h"
#include "config.h"
#include "threadengine.h"
#include "serialize.h"

namespace Mail
{
	using HeaderMap = Warden::map<Warden::string>;

	extern CoreExport bool Send(User *from, NickCore *to, BotInfo *service, const Warden::string &subject, const Warden::string &message, const HeaderMap& hm = {});
	extern CoreExport bool Send(NickCore *to, const Warden::string &subject, const Warden::string &message, const HeaderMap& hm = {});
	extern CoreExport bool Validate(const Warden::string &email);

	/** Whether mail:smtpserver is set, so mail goes to an SMTP server instead of sendmail. */
	extern CoreExport bool UseSMTP();

	/** Sends a mail through mail:smtpserver, retrying temporary failures. */
	extern CoreExport void SendSMTP(const Warden::string &send_from, const Warden::string &mail_to, const Warden::string &addr, const Warden::string &subject, const Warden::string &message, HeaderMap headers);

	/** Checks mail:sendfrom and mail:replyto, and the SMTP settings against the loaded modules.
	 * @return an error message, or an empty string if they are fine
	 */
	extern CoreExport Warden::string CheckSMTPConfig(const Configuration::Conf &conf);

	/** Logs warnings about SMTP settings that work but are unsafe. */
	extern CoreExport void WarnSMTPConfig(const Configuration::Conf &conf);

	/* A email message being sent */
	class Message final
		: public Thread
	{
	private:
		Warden::string error;
		Warden::string sendmail_path;
		Warden::string send_from;
		Warden::string mail_to;
		Warden::string addr;
		Warden::string subject;
		Warden::string message;
		HeaderMap headers;
		bool dont_quote_addresses;
		Warden::string eol;

	public:
		/** Construct this message. Once constructed call Thread::Start to launch the mail sending.
		 * @param sf Config->SendFrom
		 * @param mailto Name of person being mailed (u->nick, nc->display, etc)
		 * @param addr Destination address to mail
		 * @param subject Message subject
		 * @param message The actual message
		 * @param hm Headers to include in the email
		 */
		Message(const Warden::string &sf, const Warden::string &mailto, const Warden::string &addr, const Warden::string &subject, const Warden::string &message, const HeaderMap& hm);

		/** @nodoc */
		~Message();

		/* Called from within the thread to actually send the mail */
		void Run() override;
	};

	class CoreExport Template final
	{
	private:
		struct MessagePart final
		{
			Warden::string body;
			Warden::string content_type;
		};
		const Warden::string config;
		Warden::map<Warden::string> subjects;
		Warden::multimap<MessagePart> messages;

		bool FormatMessage(NickCore* to, const Warden::map<Warden::string> &vars, Warden::string &subject, Warden::string &message, Mail::HeaderMap &headers) const;
		void ParseMessages(const Configuration::Block &conf, Warden::multimap<MessagePart> &newmessages, const Warden::string &language, const Warden::string &ckey) const;
		void ParseSubject(const Configuration::Block &conf, Warden::map<Warden::string> &newsubjects, const Warden::string &language, const Warden::string &ckey) const;

	public:
		Template(const Warden::string &c);
		void Reload(const Configuration::Conf &conf);
		bool Send(User *from, NickCore *to, BotInfo *service, const Warden::map<Warden::string> &vars) const;
		bool Send(NickCore *to, const Warden::map<Warden::string> &vars) const;
	};

} // namespace Mail
