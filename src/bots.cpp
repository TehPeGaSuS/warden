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


#include "services.h"
#include "warden.h"
#include "bots.h"
#include "servers.h"
#include "protocol.h"
#include "xline.h"
#include "regchannel.h"
#include "channels.h"
#include "config.h"
#include "language.h"
#include "serialize.h"

Serialize::Checker<botinfo_map> BotListByNick(BOTINFO_TYPE), BotListByUID(BOTINFO_TYPE);

BotInfo::BotInfo(const Warden::string &nnick, const Warden::string &nuser, const Warden::string &nhost, const Warden::string &nreal, const Warden::string &bmodes)
	: User(nnick, nuser, nhost, "", "", Me, nreal, Warden::CurTime, "", {}, IRCD ? IRCD->UID_Retrieve() : "", NULL)
	, Serializable(BOTINFO_TYPE)
	, channels(CHANNELINFO_TYPE)
	, botmodes(bmodes)
{
	this->lastmsg = this->created = Warden::CurTime;
	this->introduced = false;
	this->oper_only = this->conf = false;

	(*BotListByNick)[this->nick] = this;
	if (!this->uid.empty())
		(*BotListByUID)[this->uid] = this;

	ctcps.emplace("CLIENTINFO", [this](auto *bi, auto *u, const auto &)
	{
		Warden::string buf;
		for (const auto &[ctcp, _] : this->ctcps)
		{
			if (!buf.empty())
				buf.push_back(' ');
			buf.append(ctcp.upper());
		}
		IRCD->SendNotice(bi, u->GetUID(), Warden::FormatCTCP("CLIENTINFO", buf));
	});
	ctcps.emplace("PING", [](auto *bi, auto *u, const auto &ctcpbody)
	{
		IRCD->SendNotice(bi, u->GetUID(), Warden::FormatCTCP("PING", ctcpbody));
	});
	ctcps.emplace("SOURCE", [](auto *bi, auto *u, const auto &)
	{
		IRCD->SendNotice(bi, u->GetUID(), Warden::FormatCTCP("SOURCE", "https://github.com/TehPeGaSuS/warden"));
	});
	ctcps.emplace("TIME", [](auto *bi, auto *u, const auto &)
	{
		IRCD->SendNotice(bi, u->GetUID(), Warden::FormatCTCP("TIME", Warden::strftime(Warden::CurTime, nullptr, true)));
	});
	ctcps.emplace("VERSION", [](auto *bi, auto *u, const auto &)
	{
		auto *enc = ModuleManager::FindFirstOf(ENCRYPTION);
		IRCD->SendNotice(bi, u->GetUID(), Warden::FormatCTCP("VERSION", Warden::Format("Warden-%s %s -- %s -- %s", Warden::Version().c_str(),
			Warden::VersionBuildString().c_str(), IRCD->GetProtocolName().c_str(), enc ? enc->name.c_str() : "(none)")));
	});

	FOREACH_MOD(OnCreateBot, (this));

	// If we're synchronised with the uplink already, send the bot.
	if (Me && Me->IsSynced())
	{
		spacesepstream modesep(this->botmodes.empty() ? IRCD->DefaultPseudoclientModes : "+" + this->botmodes);

		Warden::string modechars;
		modesep.GetToken(modechars);

		std::vector<Warden::string> modeparams;
		modesep.GetTokens(modeparams);

		if (!modechars.empty())
			this->SetModesInternal(this, modechars, modeparams);

		XLine x(this->nick, "Reserved for services");
		IRCD->SendSQLine(NULL, &x);
		IRCD->SendClientIntroduction(this);
		this->introduced = true;
	}
}

BotInfo::~BotInfo()
{
	UnsetExtensibles();

	FOREACH_MOD(OnDelBot, (this));

	// If we're synchronised with the uplink already, send the bot.
	if (Me && Me->IsSynced())
	{
		IRCD->SendQuit(this);
		FOREACH_MOD(OnUserQuit, (this, ""));
		this->introduced = false;
		XLine x(this->nick);
		IRCD->SendSQLineDel(&x);
	}

	for (auto it = this->channels->begin(), it_end = this->channels->end(); it != it_end;)
	{
		ChannelInfo *ci = *it++;
		this->UnAssign(NULL, ci);
	}

	BotListByNick->erase(this->nick);
	if (!this->uid.empty())
		BotListByUID->erase(this->uid);
}

BotInfo::Type::Type()
	: Serialize::Type(BOTINFO_TYPE)
{
}

void BotInfo::Type::Serialize(Serializable *obj, Serialize::Data &data) const
{
	const auto *bi = static_cast<const BotInfo *>(obj);
	data.Store("nick", bi->nick);
	data.Store("user", bi->ident);
	data.Store("host", bi->host);
	data.Store("realname", bi->realname);
	data.Store("created", bi->created);
	data.Store("oper_only", bi->oper_only);

	Extensible::ExtensibleSerialize(bi, bi, data);
}

Serializable *BotInfo::Type::Unserialize(Serializable *obj, Serialize::Data &data) const
{
	const auto nick = data.Load("nick");

	BotInfo *bi;
	if (obj)
		bi = warden_dynamic_static_cast<BotInfo *>(obj);
	else if (!(bi = BotInfo::Find(nick, true)))
		bi = new BotInfo(nick, data.Load("user"), data.Load("host"), data.Load("realname"));

	bi->created = data.Load<time_t>("created");
	bi->oper_only = data.Load<bool>("oper_only");

	Extensible::ExtensibleUnserialize(bi, bi, data);

	return bi;
}

void BotInfo::GenerateUID()
{
	if (this->introduced)
		throw CoreException("Changing bot UID when it is introduced?");

	if (!this->uid.empty())
	{
		BotListByUID->erase(this->uid);
		UserListByUID.erase(this->uid);
	}

	this->uid = IRCD->UID_Retrieve();
	(*BotListByUID)[this->uid] = this;
	UserListByUID[this->uid] = this;
}

void BotInfo::OnKill()
{
	this->introduced = false;
	this->GenerateUID();
	IRCD->SendClientIntroduction(this);
	this->introduced = true;

	for (const auto &[_, chan] : this->chans)
		IRCD->SendJoin(this, chan->chan, &chan->status);
}

void BotInfo::SetNewNick(const Warden::string &newnick)
{
	UserListByNick.erase(this->nick);
	BotListByNick->erase(this->nick);

	this->nick = newnick;

	UserListByNick[this->nick] = this;
	(*BotListByNick)[this->nick] = this;
}

const std::set<ChannelInfo *> &BotInfo::GetChannels() const
{
	return this->channels;
}

void BotInfo::Assign(User *u, ChannelInfo *ci)
{
	EventReturn MOD_RESULT;
	FOREACH_RESULT(OnPreBotAssign, MOD_RESULT, (u, ci, this));
	if (MOD_RESULT == EVENT_STOP)
		return;

	if (ci->bi)
		ci->bi->UnAssign(u, ci);

	ci->bi = this;
	this->channels->insert(ci);

	FOREACH_MOD(OnBotAssign, (u, ci, this));
}

void BotInfo::UnAssign(User *u, ChannelInfo *ci)
{
	EventReturn MOD_RESULT;
	FOREACH_RESULT(OnBotUnAssign, MOD_RESULT, (u, ci));
	if (MOD_RESULT == EVENT_STOP)
		return;

	if (ci->c && ci->c->FindUser(ci->bi))
	{
		if (u)
			ci->bi->Part(ci->c, "UNASSIGN from " + u->nick);
		else
			ci->bi->Part(ci->c);
	}

	ci->bi = NULL;
	this->channels->erase(ci);
}

unsigned BotInfo::GetChannelCount() const
{
	return this->channels->size();
}

void BotInfo::Join(Channel *c, ChannelStatus *status)
{
	if (c->FindUser(this) != NULL)
		return;

	c->JoinUser(this, status);
	if (IRCD)
		IRCD->SendJoin(this, c, status);

	FOREACH_MOD(OnJoinChannel, (this, c));
}

void BotInfo::Join(const Warden::string &chname, ChannelStatus *status)
{
	bool c;
	return this->Join(Channel::FindOrCreate(chname, c), status);
}

void BotInfo::Part(Channel *c, const Warden::string &reason)
{
	if (c->FindUser(this) == NULL)
		return;

	FOREACH_MOD(OnPrePartChannel, (this, c));

	IRCD->SendPart(this, c, reason);

	c->DeleteUser(this);

	FOREACH_MOD(OnPartChannel, (this, c, c->name, reason));
}

void BotInfo::OnMessage(User *u, const Warden::string &message, const Warden::map<Warden::string> &tags)
{
	if (this->commands.empty())
		return;

	Warden::string msgid;
	auto iter = tags.find("msgid");
	if (iter != tags.end())
		msgid = iter->second;

	CommandSource source(u->nick, u, u->Account(), u, this, msgid);
	Command::Run(source, message);
}

CommandInfo &BotInfo::SetCommand(const Warden::string &cname, const Warden::string &sname, const Warden::string &permission)
{
	CommandInfo ci;
	ci.name = sname;
	ci.permission = permission;
	this->commands[cname] = ci;
	return this->commands[cname];
}

CommandInfo *BotInfo::GetCommand(const Warden::string &cname)
{
	auto it = this->commands.find(cname);
	if (it != this->commands.end())
		return &it->second;
	return NULL;
}

Warden::string BotInfo::GetQueryCommand(const Warden::string &command, const Warden::string &extra) const
{
	Warden::string buf;
	if (Config->ServiceAlias && !this->alias.empty())
		buf.append("/").append(this->alias);
	else
		buf.append("/msg ").append(this->nick);

	if (!command.empty())
	{
		Warden::string actual_command;
		for (const auto &[c_name, info] : this->commands)
		{
			if (info.name != command)
				continue; // Wrong command.

			actual_command = c_name;
			if (!info.hide)
				break; // Keep going to find a non-hidden alternative.
		}

		if (actual_command.empty())
			return "\036(MISSING)\036";
		buf.append(" ").append(actual_command);
	}

	if (!extra.empty())
		buf.append(" ").append(extra);

	return buf.nobreak();
}

BotInfo *BotInfo::Find(const Warden::string &nick, bool nick_only)
{
	if (!nick_only && IRCD != NULL && IRCD->RequiresID)
	{
		auto it = BotListByUID->find(nick);
		if (it != BotListByUID->end())
		{
			BotInfo *bi = it->second;
			bi->QueueUpdate();
			return bi;
		}

		if (IRCD->AmbiguousID)
			return NULL;
	}

	auto it = BotListByNick->find(nick);
	if (it != BotListByNick->end())
	{
		BotInfo *bi = it->second;
		bi->QueueUpdate();
		return bi;
	}

	return NULL;
}
