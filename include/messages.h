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

#include "protocol.h"

/* Common IRCD messages.
 * Protocol modules may chose to include some, none, or all of these handlers
 * as they see fit.
 */

namespace Message
{

	struct CoreExport Away
		: IRCDMessage
	{
		Away(Module *creator, const Warden::string &mname = "AWAY") : IRCDMessage(creator, mname, 0) { SetFlag(FLAG_REQUIRE_USER); SetFlag(FLAG_SOFT_LIMIT); }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Capab
		: IRCDMessage
	{
		Capab(Module *creator, const Warden::string &mname = "CAPAB") : IRCDMessage(creator, mname, 1) { SetFlag(FLAG_SOFT_LIMIT); }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Error
		: IRCDMessage
	{
		Error(Module *creator, const Warden::string &mname = "ERROR") : IRCDMessage(creator, mname, 1) { }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Ignore final
		: IRCDMessage
	{
		Ignore(Module *creator, const Warden::string &mname);
		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Invite
		: IRCDMessage
	{
		Invite(Module *creator, const Warden::string &mname = "INVITE") : IRCDMessage(creator, mname, 2) { SetFlag(FLAG_REQUIRE_USER); SetFlag(FLAG_SOFT_LIMIT); }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Join
		: IRCDMessage
	{
		Join(Module *creator, const Warden::string &mname = "JOIN") : IRCDMessage(creator, mname, 1) { SetFlag(FLAG_REQUIRE_USER); SetFlag(FLAG_SOFT_LIMIT); }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;

		typedef std::pair<ChannelStatus, User *> SJoinUser;

		/** Handle a SJOIN.
		 * @param source The source of the SJOIN
		 * @param chan The channel the users are joining to
		 * @param ts The TS for the channel
		 * @param modes The mode letters sent with the SJOIN, if any
		 * @param modeparams The mode parameters sent with the SJOIN, if any
		 * @param users The users and their status, if any
		 */
		static void SJoin(MessageSource &source, const Warden::string &chan, time_t ts, const Warden::string &modes, const std::vector<Warden::string> &modeparams, const std::list<SJoinUser> &users);
	};

	struct CoreExport Kick
		: IRCDMessage
	{
		Kick(Module *creator, const Warden::string &mname = "KICK") : IRCDMessage(creator, mname, 2) { SetFlag(FLAG_SOFT_LIMIT); }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Kill
		: IRCDMessage
	{
		Kill(Module *creator, const Warden::string &mname = "KILL") : IRCDMessage(creator, mname, 2) { }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Mode
		: IRCDMessage
	{
		Mode(Module *creator, const Warden::string &mname = "MODE") : IRCDMessage(creator, mname, 2) { SetFlag(FLAG_SOFT_LIMIT); }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport MOTD
		: IRCDMessage
	{
		MOTD(Module *creator, const Warden::string &mname = "MOTD") : IRCDMessage(creator, mname, 1) { }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Notice
		: IRCDMessage
	{
		Notice(Module *creator, const Warden::string &mname = "NOTICE") : IRCDMessage(creator, mname, 2) { SetFlag(FLAG_REQUIRE_USER); }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Part
		: IRCDMessage
	{
		Part(Module *creator, const Warden::string &mname = "PART") : IRCDMessage(creator, mname, 1) { SetFlag(FLAG_REQUIRE_USER); SetFlag(FLAG_SOFT_LIMIT); }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Ping
		: IRCDMessage
	{
		Ping(Module *creator, const Warden::string &mname = "PING") : IRCDMessage(creator, mname, 1) { SetFlag(FLAG_SOFT_LIMIT); }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Privmsg
		: IRCDMessage
	{
		Privmsg(Module *creator, const Warden::string &mname = "PRIVMSG") : IRCDMessage(creator, mname, 2) { SetFlag(FLAG_REQUIRE_USER); }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Quit
		: IRCDMessage
	{
		Quit(Module *creator, const Warden::string &mname = "QUIT") : IRCDMessage(creator, mname, 1) { SetFlag(FLAG_REQUIRE_USER); }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport SQuit
		: IRCDMessage
	{
		SQuit(Module *creator, const Warden::string &mname = "SQUIT") : IRCDMessage(creator, mname, 2) { }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Stats
		: IRCDMessage
	{
		Stats(Module *creator, const Warden::string &mname = "STATS") : IRCDMessage(creator, mname, 1) { SetFlag(FLAG_REQUIRE_USER); SetFlag(FLAG_SOFT_LIMIT); }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Time
		: IRCDMessage
	{
		Time(Module *creator, const Warden::string &mname = "TIME") : IRCDMessage(creator, mname, 0) { SetFlag(FLAG_SOFT_LIMIT); }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Topic
		: IRCDMessage
	{
		Topic(Module *creator, const Warden::string &mname = "TOPIC") : IRCDMessage(creator, mname, 2) { SetFlag(FLAG_REQUIRE_USER); }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Version
		: IRCDMessage
	{
		Version(Module *creator, const Warden::string &mname = "VERSION") : IRCDMessage(creator, mname, 0) { SetFlag(FLAG_SOFT_LIMIT); }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

	struct CoreExport Whois
		: IRCDMessage
	{
		Whois(Module *creator, const Warden::string &mname = "WHOIS") : IRCDMessage(creator, mname, 1) { SetFlag(FLAG_SOFT_LIMIT); }

		void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override;
	};

} // namespace Message
