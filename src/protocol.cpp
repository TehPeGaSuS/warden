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

#include "services.h"
#include "modules.h"
#include "protocol.h"
#include "users.h"
#include "servers.h"
#include "config.h"
#include "uplink.h"
#include "bots.h"
#include "channels.h"
#include "numeric.h"

IRCDProto *IRCD = NULL;

IRCDProto::IRCDProto(Module *creator, const Warden::string &p)
	: Service(creator, "IRCDProto", creator->name)
	, proto_name(p)
	, MaxChannel(Config->GetBlock("networkinfo").Get<unsigned>("chanlen", "32"))
	, MaxHost(Config->GetBlock("networkinfo").Get<unsigned>("hostlen", "64"))
	, MaxNick(Config->GetBlock("networkinfo").Get<unsigned>("nicklen", "31"))
	, MaxUser(Config->GetBlock("networkinfo").Get<unsigned>("userlen", "10"))
{
	if (IRCD == NULL)
		IRCD = this;
}

IRCDProto::~IRCDProto()
{
	if (IRCD == this)
		IRCD = NULL;
}

static inline char nextID(int pos, Warden::string &buf)
{
	char &c = buf[pos];
	if (c == 'Z')
		c = '0';
	else if (c != '9')
		++c;
	else if (pos)
		c = 'A';
	else
		c = '0';
	return c;
}

Warden::string IRCDProto::UID_Retrieve()
{
	if (!IRCD || !IRCD->RequiresID)
		return "";

	static Warden::string current_uid = "AAAAAA";

	do
	{
		int current_len = current_uid.length() - 1;
		while (current_len >= 0 && nextID(current_len--, current_uid) == 'A');
	}
	while (User::Find(Me->GetSID() + current_uid) != NULL);

	return Me->GetSID() + current_uid;
}

Warden::string IRCDProto::SID_Retrieve()
{
	if (!IRCD || !IRCD->RequiresID)
		return "";

	static Warden::string current_sid = Config->GetBlock("serverinfo").Get<const Warden::string>("id");
	if (current_sid.empty())
		current_sid = "00A";

	do
	{
		int current_len = current_sid.length() - 1;
		while (current_len >= 0 && nextID(current_len--, current_sid) == 'A');
	}
	while (Server::Find(current_sid) != NULL);

	return current_sid;
}

time_t IRCDProto::ExtractTimestamp(const Warden::string &str)
{
	auto ts = Warden::TryConvert<time_t>(str);
	if (!ts.has_value())
		throw ProtocolException("Invalid timestamp: " + str);
	return ts.value();
}

void IRCDProto::SendError(const Warden::string &reason)
{
	Uplink::Send("ERROR", reason);
}

void IRCDProto::SendKill(const MessageSource &source, const Warden::string &target, const Warden::string &reason)
{
	Uplink::Send(source, "KILL", target, reason);
}

void IRCDProto::SendSVSKill(const MessageSource &source, User *user, const Warden::string &buf)
{
	Uplink::Send(source, "KILL", user->GetUID(), buf);
}

static auto BuildModeChange(const ModeManager::Change &change)
{
	std::list<std::pair<Warden::string, std::vector<Warden::string>>> modes;

	Warden::string modebuf;
	size_t modecount = 0;
	std::vector<Warden::string> parambuf;
	size_t paramlen = 0;

	auto adding = true;
	for (const auto &[mode, info] : change)
	{
		const auto reached_max_line = IRCD->MaxLine && modebuf.length() + paramlen > IRCD->MaxLine - 100; // Leave room for command, channel, etc
		const auto reached_max_modes = IRCD->MaxModes && ++modecount > IRCD->MaxModes;
		if (reached_max_modes || reached_max_line)
		{
			modes.push_back({modebuf, parambuf});

			modebuf.clear();
			modecount = 0;

			parambuf.clear();
			paramlen = 0;
		}

		// Push the mode.
		const auto direction = info.first;
		if (modebuf.empty() || adding != direction)
		{
			adding = direction;
			modebuf += (adding ? '+' : '-');
		}
		modebuf += mode->mchar;

		// If it has a value push that too.
		const auto &data = info.second;
		if (!data.value.empty())
		{
			parambuf.push_back(data.value);
			paramlen += data.value.length() + 1;
		}
	}

	if (!modebuf.empty())
		modes.push_back({modebuf, parambuf});

	return modes;
}

void IRCDProto::SendMode(const MessageSource &source, Channel *chan, const ModeManager::Change &change)
{
	for (const auto &[modes, params] : BuildModeChange(change))
		IRCD->SendModeInternal(source, chan, modes, params);
}

void IRCDProto::SendModeInternal(const MessageSource &source, Channel *chan, const Warden::string &modes, const std::vector<Warden::string> &values)
{
	auto params = values;
	params.insert(params.begin(), { chan->name, modes });
	Uplink::SendInternal({}, source, "MODE", params);
}

void IRCDProto::SendMode(const MessageSource &source, User *dest, const ModeManager::Change &change)
{
	for (const auto &[modes, params] : BuildModeChange(change))
		IRCD->SendModeInternal(source, dest, modes, params);
}

void IRCDProto::SendModeInternal(const MessageSource &source, User *dest, const Warden::string &modes, const std::vector<Warden::string> &values)
{
	auto params = values;
	params.insert(params.begin(), { dest->GetUID(), modes });
	Uplink::SendInternal({}, source, "MODE", params);
}

void IRCDProto::SendKick(const MessageSource &source, const Channel *c, User *u, const Warden::string &r)
{
	if (!r.empty())
		Uplink::Send(source, "KICK", c->name, u->GetUID(), r);
	else
		Uplink::Send(source, "KICK", c->name, u->GetUID());
}

void IRCDProto::SendNotice(const MessageSource &source, const Warden::string &dest, const Warden::string &msg, const Warden::map<Warden::string> &tags)
{
	Uplink::Send(tags, source, "NOTICE", dest, msg.empty() ? " " : msg);
}

void IRCDProto::SendPrivmsg(const MessageSource &source, const Warden::string &dest, const Warden::string &msg, const Warden::map<Warden::string> &tags)
{
	Uplink::Send(tags, source, "PRIVMSG", dest, msg.empty() ? " " : msg);
}

void IRCDProto::SendTagmsg(const MessageSource &source, const Warden::string &dest, const Warden::map<Warden::string> &tags)
{
	if (CanTagMessage)
		Uplink::Send(tags, source, "TAGMSG", dest);
}

void IRCDProto::SendQuit(User *u, const Warden::string &buf, const Warden::string &operbuf)
{
	if (!buf.empty())
		Uplink::Send(u, "QUIT", buf);
	else
		Uplink::Send(u, "QUIT");
}

void IRCDProto::SendPart(User *u, const Channel *chan, const Warden::string &buf)
{
	if (!buf.empty())
		Uplink::Send(u, "PART", chan->name, buf);
	else
		Uplink::Send(u, "PART", chan->name);
}

void IRCDProto::SendGlobops(const MessageSource &source, const Warden::string &message)
{
	Uplink::Send(source, "GLOBOPS", message);
}

void IRCDProto::SendNumericInternal(unsigned numeric, const Warden::string &dest, const std::vector<Warden::string> &params)
{
	Warden::string n = Warden::ToString(numeric);
	if (numeric < 10)
		n = "0" + n;
	if (numeric < 100)
		n = "0" + n;

	auto newparams = params;
	newparams.insert(newparams.begin(), dest);
	Uplink::SendInternal({}, Me, n, newparams);
}

void IRCDProto::SendTopic(const MessageSource &source, Channel *c)
{
	Uplink::Send(source, "TOPIC", c->name, c->topic);
}

void IRCDProto::SendPing(const Warden::string &servname, const Warden::string &who)
{
	if (servname.empty())
		Uplink::Send("PING", who);
	else
		Uplink::Send("PING", servname, who);
}

/**
 * Send a PONG reply to a received PING.
 * servname should be left NULL to send a one param reply.
 * @param servname Daemon or client that is responding to the PING.
 * @param who Origin of the PING and destination of the PONG message.
 **/
void IRCDProto::SendPong(const Warden::string &servname, const Warden::string &who)
{
	if (servname.empty())
		Uplink::Send("PONG", who);
	else
		Uplink::Send("PONG", servname, who);
}

void IRCDProto::SendInvite(const MessageSource &source, const Channel *c, User *u)
{
	Uplink::Send(source, "INVITE", u->GetUID(), c->name);
}

void IRCDProto::SendSquit(Server *s, const Warden::string &message)
{
	Uplink::Send("SQUIT", s->GetSID(), message);
}

void IRCDProto::SendNickChange(User *u, const Warden::string &newnick)
{
	Uplink::Send(u, "NICK", newnick, Warden::CurTime);
}

void IRCDProto::SendForceNickChange(User *u, const Warden::string &newnick, time_t when)
{
	Uplink::Send("SVSNICK", u->GetUID(), newnick, when);
}

bool IRCDProto::IsNickValid(const Warden::string &nick)
{
	/**
	 * RFC: definition of a valid nick
	 * nickname =  ( letter / special ) ( letter / digit / special / "-" )
	 * letter   =  A-Z / a-z
	 * digit    =  0-9
	 * special  =  [, ], \, `, _, ^, {, |, }
	 **/

	 if (nick.empty())
		return false;

	Warden::string special = "[]\\`_^{|}";

	for (unsigned i = 0; i < nick.length(); ++i)
		if ((nick[i] < 'A' || nick[i] > 'Z') && (nick[i] < 'a' || nick[i] > 'z')
		  && special.find(nick[i]) == Warden::string::npos
		  && (Config && Config->NickChars.find(nick[i]) == Warden::string::npos)
		  && (!i || ((nick[i] < '0' || nick[i] > '9') && nick[i] != '-')))
			return false;

	return true;
}

bool IRCDProto::IsChannelValid(const Warden::string &chan)
{
	if (chan.empty() || chan[0] != '#' || chan.length() > IRCD->MaxChannel)
		return false;

	if (chan.find_first_of(" ,") != Warden::string::npos)
		return false;

	return true;
}

bool IRCDProto::IsIdentValid(const Warden::string &ident)
{
	if (ident.empty() || ident.length() > IRCD->MaxUser)
		return false;

	for (auto c : ident)
	{
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-')
			continue;

		return false;
	}

	return true;
}

bool IRCDProto::IsHostValid(const Warden::string &host)
{
	if (host.empty() || host.length() > IRCD->MaxHost)
		return false;

	const auto &block = Config->GetBlock("networkinfo");
	const auto &vhostdisablebe = block.Get<const Warden::string>("disallow_start_or_end", ".-/");
	const auto &vhostchars = block.Get<const Warden::string>("vhost_chars", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-/");

	if (vhostdisablebe.find_first_of(host[0]) != Warden::string::npos)
		return false;
	else if (vhostdisablebe.find_first_of(host[host.length() - 1]) != Warden::string::npos)
		return false;

	int dots = 0;
	for (auto chr : host)
	{
		if (chr == '.')
			++dots;
		if (vhostchars.find_first_of(chr) == Warden::string::npos)
			return false;
	}

	return dots > 0 || Config->GetBlock("networkinfo").Get<bool>("allow_undotted_vhosts");
}

void IRCDProto::SendOper(User *u)
{
	SendNumeric(RPL_YOUREOPER, u->GetUID(), "You are now an IRC operator (set by services)");
	u->SetMode(NULL, "OPER");
}

size_t IRCDProto::GetMaxListFor(Channel *c, ChannelMode *cm)
{
	return c->HasMode("LBAN") ? 0 : Config->GetBlock("networkinfo").Get<size_t>("modelistsize", "100");
}

Warden::string IRCDProto::NormalizeMask(const Warden::string &mask)
{
	if (IsExtbanValid(mask))
		return mask;
	return Entry(mask).GetCleanMask();
}

void IRCDProto::SendContextNotice(BotInfo *bi, User *target, Channel *context, const Warden::string &msg, const Warden::map<Warden::string> &tags)
{
	auto newtags = tags;
	newtags["+channel-context"] = context->name;
	IRCD->SendNotice(bi, target->GetUID(), Warden::Format("[%s] %s", context->name.c_str(), msg.c_str()), newtags);
}

void IRCDProto::SendContextPrivmsg(BotInfo *bi, User *target, Channel *context, const Warden::string &msg, const Warden::map<Warden::string> &tags)
{
	auto newtags = tags;
	newtags["+channel-context"] = context->name;
	IRCD->SendPrivmsg(bi, target->GetUID(), Warden::Format("[%s] %s", context->name.c_str(), msg.c_str()), newtags);
}

MessageSource::MessageSource(const Warden::string &src) : source(src)
{
	/* no source for incoming message is our uplink */
	if (src.empty())
		this->s = Servers::GetUplink();
	else if (IRCD->RequiresID || src.find('.') != Warden::string::npos)
		this->s = Server::Find(src);
	if (this->s == NULL)
		this->u = User::Find(src);
}

MessageSource::MessageSource(User *_u) : source(_u ? _u->nick : ""), u(_u)
{
}

MessageSource::MessageSource(Server *_s) : source(_s ? _s->GetName() : ""), s(_s)
{
}

const Warden::string &MessageSource::GetName() const
{
	if (this->s)
		return this->s->GetName();
	else if (this->u)
		return this->u->nick;
	else
		return this->source;
}

const Warden::string &MessageSource::GetSource() const
{
	return this->source;
}

User *MessageSource::GetUser() const
{
	return this->u;
}

BotInfo *MessageSource::GetBot() const
{
	return BotInfo::Find(this->GetName(), true);
}

Server *MessageSource::GetServer() const
{
	return this->s;
}

IRCDMessage::IRCDMessage(Module *o, const Warden::string &n, size_t pc)
	: Service(o, "IRCDMessage", o->name + "/" + n.lower())
	, name(n)
	, param_count(pc)
{
}
