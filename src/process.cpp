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
#include "servers.h"
#include "users.h"
#include "regchannel.h"
#include "uplink.h"

void Warden::Process(const Warden::string &buffer)
{
	if (buffer.empty())
		return;

	Warden::map<Warden::string> tags;
	Warden::string source, command;
	std::vector<Warden::string> params;
	if (!IRCD->Parse(buffer, tags, source, command, params))
		return;

	Log(LOG_RAWIO) << "Received " << buffer;
	if (Warden::ProtocolDebug)
	{
		if (tags.empty())
			Log() << "\tNo tags";
		else
		{
			for (const auto &[tname, tvalue] : tags)
				Log() << "\tTag " << tname << ": " << tvalue;
		}

		if (source.empty())
			Log() << "\tNo source";
		else
			Log() << "\tSource: " << source;

		Log() << "\tCommand: " << command;

		if (params.empty())
			Log() << "\tNo params";
		else
		{
			for (size_t i = 0; i < params.size(); ++i)
				Log() << "\tParam " << i << ": " << params[i];
		}
	}

	MessageSource src(source);
	EventReturn MOD_RESULT;
	FOREACH_RESULT(OnMessage, MOD_RESULT, (src, command, params, tags));
	if (MOD_RESULT == EVENT_STOP)
		return;

	ProcessInternal(src, command, params, tags);
}

void Warden::ProcessInternal(MessageSource &src, const Warden::string &command, const std::vector<Warden::string> &params, const Warden::map<Warden::string> & tags)
{
	static const Warden::string proto_name = ModuleManager::FindFirstOf(PROTOCOL) ? ModuleManager::FindFirstOf(PROTOCOL)->name : "";
	ServiceReference<IRCDMessage> m("IRCDMessage", proto_name + "/" + command.lower());
	if (!m)
	{
		Log(LOG_DEBUG) << "unknown message from server: " << command;
		return;
	}

	if (m->HasFlag(IRCDMessage::FLAG_SOFT_LIMIT) ? (params.size() < m->GetParamCount()) : (params.size() != m->GetParamCount()))
		Log(LOG_DEBUG) << "invalid parameters for " << command << ": " << params.size() << " != " << m->GetParamCount();
	else if (m->HasFlag(IRCDMessage::FLAG_REQUIRE_USER) && !src.GetUser())
		Log(LOG_DEBUG) << "unexpected non-user source " << src.GetSource() << " for " << command;
	else if (m->HasFlag(IRCDMessage::FLAG_REQUIRE_SERVER) && !src.GetSource().empty() && !src.GetServer())
		Log(LOG_DEBUG) << "unexpected non-server source " << src.GetSource() << " for " << command;
	else
	{
		try
		{
			UplinkSock->recv_msgs++;
			m->Run(src, params, tags);
		}
		catch (const ProtocolException &err)
		{
			IRCD->SendError(err.GetReason());
			Warden::QuitReason = "Protocol error: " + err.GetReason();
			Warden::Quitting = true;
			Warden::ReturnValue = EXIT_FAILURE;
		}
	}
}

void IRCDProto::PopulateTags(Warden::map<Warden::string> &tags, const MessageSource &source, const Warden::string &command, const std::vector<Warden::string> &params)
{
	auto it = tags.find("time"); // https://ircv3.net/specs/extensions/server-time
	if (it == tags.end())
		tags["time"] = Warden::FormatISO8601(Warden::CurTime, Warden::CurTimeNs / 1'000'000);
}

bool IRCDProto::Parse(const Warden::string &buffer, Warden::map<Warden::string> &tags, Warden::string &source, Warden::string &command, std::vector<Warden::string> &params)
{
	MessageTokenizer tokens(buffer);

	// This will always exist because of the check in Warden::Process.
	Warden::string token;
	tokens.GetMiddle(token);

	if (token[0] == '@')
	{
		// The line begins with message tags.
		sepstream tagstream(token.substr(1), ';');
		while (tagstream.GetToken(token))
		{
			const Warden::string::size_type valsep = token.find('=');
			if (valsep == Warden::string::npos)
			{
				// Tag has no value.
				tags[token];
			}
			else
			{
				// Tag has a value
				tags[token.substr(0, valsep)] = token.substr(valsep + 1);
			}
		}

		if (!tokens.GetMiddle(token))
			return false;
	}

	if (token[0] == ':')
	{
		source = token.substr(1);
		if (!tokens.GetMiddle(token))
			return false;
	}

	// Store the command name.
	command = token;

	// Retrieve all of the parameters.
	while (tokens.GetTrailing(token))
		params.push_back(token);

	return true;
}

bool IRCDProto::Format(Warden::string &message, const Warden::map<Warden::string> &tags, const MessageSource &source, const Warden::string &command, const std::vector<Warden::string> &params)
{
	std::stringstream buffer;
	if (!tags.empty())
	{
		char separator = '@';
		for (const auto &[tname, tvalue] : tags)
		{
			if (IRCD->IsTagValid(tname, tvalue))
			{
				buffer << separator << tname;
				if (!tvalue.empty())
					buffer << '=' << tvalue;
				separator = ';';
			}
		}
		if (separator != '@')
			buffer << ' ';
	}

	if (source.GetServer())
	{
		const auto *s = source.GetServer();
		if (s != Me && !s->IsJuped())
		{
			Log(LOG_DEBUG) << "Attempted to send \"" << command << "\" from " << s->GetName() << " who is not from me";
			return false;
		}

		buffer << ':' << s->GetSID() << ' ';
	}
	else if (source.GetUser())
	{
		const auto *u = source.GetUser();
		if (u->server != Me && !u->server->IsJuped())
		{
			Log(LOG_DEBUG) << "Attempted to send \"" << command << "\" from " << u->nick << " who is not from me";
			return false;
		}

		const auto *bi = source.GetBot();
		if (bi && !bi->introduced)
		{
			Log(LOG_DEBUG) << "Attempted to send \"" << command << "\" from " << bi->nick << " when not introduced";
			return false;
		}

		buffer << ':' << u->GetUID() << ' ';
	}

	buffer << command;
	if (!params.empty())
	{
		buffer << ' ';
		for (auto it = params.begin(); it != params.end() - 1; ++it)
			buffer << *it << ' ';


		const auto &last = params.back();
		if (last.empty() || last[0] == ':' || last.find(' ') != Warden::string::npos)
			buffer << ':';
		buffer << last;
	}

	message = buffer.str();
	return true;
}

MessageTokenizer::MessageTokenizer(const Warden::string &msg)
	: message(msg)
{
}

bool MessageTokenizer::GetMiddle(Warden::string &token)
{
	// If we are past the end of the string we can't do anything.
	if (position >= message.length())
	{
		token.clear();
		return false;
	}

	// If we can't find another separator this is the last token in the message.
	Warden::string::size_type separator = message.find(' ', position);
	if (separator == Warden::string::npos)
	{
		token = message.substr(position);
		position = message.length();
		return true;
	}

	token = message.substr(position, separator - position);
	position = message.find_first_not_of(' ', separator);
	return true;
}

bool MessageTokenizer::GetTrailing(Warden::string &token)
{
	// If we are past the end of the string we can't do anything.
	if (position >= message.length())
	{
		token.clear();
		return false;
	}

	// If this is true then we have a <trailing> token!
	if (message[position] == ':')
	{
		token = message.substr(position + 1);
		position = message.length();
		return true;
	}

	// There is no <trailing> token so it must be a <middle> token.
	return GetMiddle(token);
}
