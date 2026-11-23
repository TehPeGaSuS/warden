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

#include "sockets.h"
#include "protocol.h"
#include "servers.h"

namespace Uplink
{
	extern void Connect();
	extern CoreExport void SendInternal(const Warden::map<Warden::string> &, const MessageSource &, const Warden::string &, const std::vector<Warden::string> &);

	template<typename... Args>
	void Send(const Warden::map<Warden::string> &tags, const MessageSource &source, const Warden::string &command, Args &&...args)
	{
		SendInternal(tags, source, command, { Warden::ToString(args)... });
	}

	template<typename... Args>
	void Send(const Warden::map<Warden::string> &tags, const Warden::string &command, Args &&...args)
	{
		SendInternal(tags, Me, command, { Warden::ToString(args)... });
	}

	template<typename... Args>
	void Send(const MessageSource &source, const Warden::string &command, Args &&...args)
	{
		SendInternal({}, source, command, { Warden::ToString(args)... });
	}

	template<typename... Args>
	void Send(const Warden::string &command, Args &&...args)
	{
		SendInternal({}, Me, command, { Warden::ToString(args)... });
	}
}

/* This is the socket to our uplink */
class UplinkSocket final
	: public ConnectionSocket
	, public BufferedSocket
{
public:
	bool error = false;
	size_t recv_msgs = 0;
	size_t sent_msgs = 0;
	/* When we last received data from the uplink, and whether we pinged it since. */
	time_t last_read;
	bool pinged = false;
	UplinkSocket();
	~UplinkSocket();
	bool ProcessRead() override;
	void OnConnect() override;
	void OnError(const Warden::string &) override;
};
extern CoreExport UplinkSocket *UplinkSock;
