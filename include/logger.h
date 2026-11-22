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
#include "defs.h"

enum LogType
{
	/* Used whenever an administrator uses an administrative command */
	LOG_ADMIN,
	/* Used whenever an administrator overrides something, such as adding
	 * access to a channel where they don't have permission to.
	 */
	LOG_OVERRIDE,
	/* Any other command usage */
	LOG_COMMAND,
	LOG_SERVER,
	LOG_CHANNEL,
	LOG_USER,
	LOG_MODULE,
	LOG_NORMAL,
	LOG_TERMINAL,
	LOG_RAWIO,
	LOG_DEBUG,
	LOG_DEBUG_2,
	LOG_DEBUG_3,
	LOG_DEBUG_4
};

struct LogFile final
{
	Warden::string filename;
	std::ofstream stream;

	LogFile(const Warden::string &name);
	~LogFile();
	const Warden::string &GetName() const;
};

/* Represents a single log message */
class CoreExport Log final
{
public:
	/* Bot that should log this message */
	BotInfo *bi = nullptr;
	/* For commands, the user executing the command, but might not always exist */
	User *u = nullptr;
	/* For commands, the account executing the command, but will not always exist */
	NickCore *nc = nullptr;
	/* For commands, the command being executed */
	Command *c = nullptr;
	/* For commands, the command source */
	CommandSource *source = nullptr;
	/* Used for LOG_CHANNEL */
	Channel *chan = nullptr;
	/* For commands, the channel the command was executed on, will not always exist */
	const ChannelInfo *ci = nullptr;
	/* For LOG_SERVER */
	Server *s = nullptr;
	/* For LOG_MODULE */
	Module *m = nullptr;
	LogType type;
	Warden::string category;

	std::stringstream buf;

	Log(LogType type = LOG_NORMAL, const Warden::string &category = "", BotInfo *bi = NULL);

	/* LOG_COMMAND/OVERRIDE/ADMIN */
	Log(LogType type, CommandSource &source, Command *c, ChannelInfo *ci = NULL);

	/* LOG_CHANNEL */
	Log(User *u, Channel *c, const Warden::string &category = "");

	/* LOG_USER */
	Log(User *u, const Warden::string &category = "", BotInfo *bi = NULL);

	/* LOG_SERVER */
	Log(Server *s, const Warden::string &category = "", BotInfo *bi = NULL);

	Log(BotInfo *b, const Warden::string &category = "");

	Log(Module *m, const Warden::string &category = "", BotInfo *bi = NULL);

	~Log();

private:
	Warden::string FormatSource() const;
	Warden::string FormatCommand() const;

public:
	Warden::string BuildPrefix() const;

	template<typename T> Log &operator<<(T val)
	{
		this->buf << val;
		return *this;
	}
};

/* Configured in the configuration file, actually does the message logging */
class CoreExport LogInfo final
{
public:
	BotInfo *bot = nullptr;
	std::vector<Warden::string> targets;
	std::vector<LogFile *> logfiles;
	int last_day = 0;
	std::vector<Warden::string> sources;
	int log_age;
	std::vector<Warden::string> admin;
	std::vector<Warden::string> override;
	std::vector<Warden::string> commands;
	std::vector<Warden::string> servers;
	std::vector<Warden::string> users;
	std::vector<Warden::string> channels;
	std::vector<Warden::string> normal;
	bool raw_io;
	bool debug;

	LogInfo(int logage, bool rawio, bool debug);

	~LogInfo();

	void OpenLogFiles();

	bool HasType(LogType ltype, const Warden::string &type) const;

	/* Logs the message l if configured to */
	void ProcessMessage(const Log *l);
};
