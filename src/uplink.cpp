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

#include "uplink.h"
#include "logger.h"
#include "config.h"
#include "protocol.h"
#include "servers.h"

UplinkSocket *UplinkSock = NULL;

class ReconnectTimer final
	: public Timer
{
public:
	ReconnectTimer(time_t wait)
		: Timer(wait)
	{
	}

	bool Tick() override
	{
		try
		{
			Uplink::Connect();
		}
		catch (const SocketException &ex)
		{
			Log(LOG_TERMINAL) << "Unable to connect to uplink #" << (Warden::CurrentUplink + 1) << " (" << Config->Uplinks[Warden::CurrentUplink].str() << "): " << ex.GetReason();
		}
		return false;
	}
};

// Notices an uplink that went silent without closing the connection
// (anope/anope#410): ping it after pingfreq of silence and drop the link if
// nothing arrives within pingtimeout.
static unsigned uplink_generation = 0;

class UplinkPingTimer final
	: public Timer
{
	unsigned generation;

public:
	UplinkPingTimer(unsigned gen)
		: Timer(5)
		, generation(gen)
	{
	}

	bool Tick() override
	{
		if (!UplinkSock || generation != uplink_generation)
			return false;
		if (!UplinkSock->flags[SF_CONNECTED])
			return true;

		const auto &block = Config->GetBlock("options");
		const auto freq = block.Get<time_t>("pingfreq", "2m");
		const auto timeout = block.Get<time_t>("pingtimeout", "1m");
		if (!freq)
			return true;

		const auto idle = Warden::CurTime - UplinkSock->last_read;
		if (idle >= freq + timeout)
		{
			UplinkSock->OnError("Ping timeout: " + Warden::ToString(idle) + " seconds");
			delete UplinkSock;
			return false;
		}

		auto *uplink = Servers::GetUplink();
		if (idle >= freq && !UplinkSock->pinged && uplink && IRCD)
		{
			UplinkSock->pinged = true;
			IRCD->SendPing(Me->GetName(), uplink->GetSID());
		}
		return true;
	}
};

void Uplink::Connect()
{
	if (Config->Uplinks.empty())
	{
		Log() << "Warning: There are no configured uplinks.";
		return;
	}

	if (++Warden::CurrentUplink >= Config->Uplinks.size())
		Warden::CurrentUplink = 0;

	Configuration::Uplink &u = Config->Uplinks[Warden::CurrentUplink];

	new UplinkSocket();
	if (!Config->GetBlock("serverinfo").Get<const Warden::string>("localhost").empty())
		UplinkSock->Bind(Config->GetBlock("serverinfo").Get<const Warden::string>("localhost"));
	FOREACH_MOD(OnPreServerConnect, ());
	Warden::string ip = Warden::Resolve(u.host, u.protocol);
	Log(LOG_TERMINAL) << "Attempting to connect to uplink #" << (Warden::CurrentUplink + 1) << " " << ip << " (" << u.str() << ")";
	UplinkSock->Connect(ip, u.port);
}

void Uplink::SendInternal(const Warden::map<Warden::string> &tags, const MessageSource &source, const Warden::string &command, const std::vector<Warden::string> &params)
{
	if (!UplinkSock)
	{
		Log(LOG_DEBUG) << "Attempted to send \"" << command << "\" from " << source.GetName() << " with a null uplink socket";
		return;
	}

	Warden::map<Warden::string> fulltags(tags);
	IRCD->PopulateTags(fulltags, source, command, params);

	Warden::string message;
	if (!IRCD->Format(message, fulltags, source, command, params))
		return;

	UplinkSock->sent_msgs++;
	UplinkSock->Write(message);

	Log(LOG_RAWIO) << "Sent " << message;
	if (Warden::ProtocolDebug)
	{
		auto sent_tag = false;
		for (const auto &[tname, tvalue] : fulltags)
		{
			if (IRCD->IsTagValid(tname, tvalue))
			{
				Log() << "\tTag " << tname << ": " << tvalue;
				sent_tag = true;
			}
		}
		if (!sent_tag)
			Log() << "\tNo tags";

		if (source.GetSource().empty())
			Log() << "\tNo source";
		else
			Log() << "\tSource: " << source.GetSource();

		Log() << "\tCommand: " << command;

		if (params.empty())
			Log() << "\tNo params";
		else
		{
			for (size_t i = 0; i < params.size(); ++i)
				Log() << "\tParam " << i << ": " << params[i];
		}
	}
}

UplinkSocket::UplinkSocket() : Socket(-1, Config->Uplinks[Warden::CurrentUplink].protocol), ConnectionSocket(), BufferedSocket()
	, last_read(Warden::CurTime)
{
	UplinkSock = this;
	new UplinkPingTimer(++uplink_generation);
}

UplinkSocket::~UplinkSocket()
{
	if (!error && !Warden::Quitting)
	{
		this->OnError("");

		std::vector<Warden::string> advice = {
			"You are connecting Warden to an SSL-only port without configuring SSL (or vice versa).",
		};
		if (IRCD)
		{
			advice.push_back(Warden::Format("You are using the wrong protocol module (currently %s for %s).",
				IRCD->owner->name.c_str(), IRCD->GetProtocolName().c_str()));
			IRCD->GetLinkAdvice(advice);
		}

		Log(LOG_TERMINAL) << "Potential causes include:";
		for (const auto &line : advice)
			Log(LOG_TERMINAL) << "* " << line;
	}

	if (IRCD && Servers::GetUplink() && Servers::GetUplink()->IsSynced())
	{
		FOREACH_MOD(OnServerDisconnect, ());

		for (const auto &[_, u] : UserListByNick)
		{
			if (u->server == Me)
			{
				/* Don't use quitmsg here, it may contain information you don't want people to see */
				const auto *reason = Warden::Restarting ? "Restarting" : "Shutting down";
				IRCD->SendQuit(u, reason, Warden::QuitReason);
				BotInfo *bi = BotInfo::Find(u->GetUID());
				if (bi != NULL)
					bi->introduced = false;
			}
		}

		IRCD->SendSquit(Me, Warden::QuitReason);
	}

	for (unsigned i = Me->GetLinks().size(); i > 0; --i)
		if (!Me->GetLinks()[i - 1]->IsJuped())
			Me->GetLinks()[i - 1]->Delete(Me->GetName() + " " + Me->GetLinks()[i - 1]->GetName());

	this->ProcessWrite(); // Write out the last bit
	UplinkSock = NULL;

	Me->Unsync();

	if (Warden::AtTerm())
	{
		if (static_cast<unsigned>(Warden::CurrentUplink + 1) == Config->Uplinks.size())
		{
			Warden::QuitReason = "Unable to connect to any uplink";
			Warden::Quitting = true;
			Warden::ReturnValue = -1;
		}
		else
		{
			new ReconnectTimer(1);
		}
	}
	else if (!Warden::Quitting)
	{
		time_t retry = Config->GetBlock("options").Get<time_t>("retrywait");

		Log() << "Disconnected, retrying in " << retry << " seconds";
		new ReconnectTimer(retry);
	}
}

bool UplinkSocket::ProcessRead()
{
	bool b = BufferedSocket::ProcessRead();
	this->last_read = Warden::CurTime;
	this->pinged = false;
	for (Warden::string buf; !(buf = this->GetLine()).empty();)
	{
		Warden::Process(buf);
		User::QuitUsers();
		Channel::DeleteChannels();
	}
	return b;
}

void UplinkSocket::OnConnect()
{
	this->last_read = Warden::CurTime;
	Log(LOG_TERMINAL) << "Successfully connected to uplink #" << (Warden::CurrentUplink + 1) << " " << Config->Uplinks[Warden::CurrentUplink].str();
	IRCD->SendConnect();
	FOREACH_MOD(OnServerConnect, ());
}

void UplinkSocket::OnError(const Warden::string &err)
{
	Warden::string what = !this->flags[SF_CONNECTED] ? "Unable to connect to" : "Lost connection from";
	Log(LOG_TERMINAL) << what << " uplink #" << (Warden::CurrentUplink + 1) << " (" << Config->Uplinks[Warden::CurrentUplink].str() << ")" << (!err.empty() ? (": " + err) : "");
	error |= !err.empty();
}
