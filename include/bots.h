// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2003-2026 Anope Contributors
// Copyright (C) 2026 Warden Contributors
// Copyright (C) 2008-2011 Robin Burchell <w00t@inspircd.org>
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

#include "users.h"
#include "warden.h"
#include "serialize.h"
#include "commands.h"


typedef Warden::map<BotInfo *> botinfo_map;

extern CoreExport Serialize::Checker<botinfo_map> BotListByNick, BotListByUID;

/* A service bot (NickServ, ChanServ, a BotServ bot, etc). */
class CoreExport BotInfo final
	: public User
	, public Serializable
{
public:
	struct Type final
		: public Serialize::Type
	{
		Type();
		void Serialize(Serializable *obj, Serialize::Data &data) const override;
		Serializable *Unserialize(Serializable *obj, Serialize::Data &data) const override;
	};

private:
	/* Channels this bot is assigned to */
	Serialize::Checker<std::set<ChannelInfo *> > channels;
public:
	time_t created;
	/* Last time this bot said something (via privmsg) */
	time_t lastmsg;
	/* Map of actual command names -> service name/permission required */
	CommandInfo::map commands;
	/** CTCP responses this bot can send. */
	Warden::map<std::function<void(BotInfo *, User *, const Warden::string &)>> ctcps;
	/* The server-side alias used to message this bot. */
	Warden::string alias;
	/* Modes the bot should have as configured in service:modes */
	Warden::string botmodes;
	/* Channels the bot should be in as configured in service:channels */
	std::vector<Warden::string> botchannels;
	/* Whether or not this bot is introduced to the network */
	bool introduced;
	/* Bot can only be assigned by irc ops */
	bool oper_only;
	/* Bot is defined in the configuration file */
	bool conf;

	/** Create a new bot.
	 * @param nick The nickname to assign to the bot.
	 * @param user The ident to give the bot.
	 * @param host The hostname to give the bot.
	 * @param real The realname to give the bot.
	 * @param bmodes The modes to give the bot.
	 */
	BotInfo(const Warden::string &nick, const Warden::string &user = "", const Warden::string &host = "", const Warden::string &real = "", const Warden::string &bmodes = "");

	/** Destroy a bot, clearing up appropriately.
	 */
	virtual ~BotInfo();

	void Serialize(Serialize::Data &data) const;
	static Serializable *Unserialize(Serializable *obj, Serialize::Data &);

	void GenerateUID();

	void OnKill();

	/** Change the nickname for the bot.
	 * @param newnick The nick to change to
	 */
	void SetNewNick(const Warden::string &newnick);

	/** Return the channels this bot is assigned to
	 */
	const std::set<ChannelInfo *> &GetChannels() const;

	/** Assign this bot to a given channel, removing the existing assigned bot if one exists.
	 * @param u The user assigning the bot, or NULL
	 * @param ci The channel registration to assign the bot to.
	 */
	void Assign(User *u, ChannelInfo *ci);

	/** Remove this bot from a given channel.
	 * @param u The user requesting the unassign, or NULL.
	 * @param ci The channel registration to remove the bot from.
	 */
	void UnAssign(User *u, ChannelInfo *ci);

	/** Get the number of channels this bot is assigned to
	 */
	unsigned GetChannelCount() const;

	/** Join this bot to a channel
	 * @param c The channel
	 * @param status The status the bot should have on the channel
	 */
	void Join(Channel *c, ChannelStatus *status = NULL);

	/** Join this bot to a channel
	 * @param chname The channel name
	 * @param status The status the bot should have on the channel
	 */
	void Join(const Warden::string &chname, ChannelStatus *status = NULL);

	/** Part this bot from a channel
	 * @param c The channel
	 * @param reason The reason we're parting
	 */
	void Part(Channel *c, const Warden::string &reason = "");

	/** Called when a user messages this bot
	 * @param u The user
	 * @param message The users' message
	 * @params tags Message tags
	 */
	void OnMessage(User *u, const Warden::string &message, const Warden::map<Warden::string> &tags);

	/** Link a command name to a command in services
	 * @param cname The command name
	 * @param sname The service name
	 * @param permission Permission required to execute the command, if any
	 * @return The commandinfo for the newly created command
	 */
	CommandInfo &SetCommand(const Warden::string &cname, const Warden::string &sname, const Warden::string &permission = "");

	/** Get command info for a command
	 * @param cname The command name
	 * @return A struct containing service name and permission
	 */
	CommandInfo *GetCommand(const Warden::string &cname);

	/** Get the command that users can use to send a message to this bot. */
	Warden::string GetQueryCommand(const Warden::string &command = "", const Warden::string &extra = "") const;

	/** Find a bot by nick
	 * @param nick The nick
	 * @param nick_only True to only look by nick, and not by UID
	 * @return The bot, if it exists
	 */
	static BotInfo *Find(const Warden::string &nick, bool nick_only = false);
};
