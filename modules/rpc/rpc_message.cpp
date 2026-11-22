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

#include "module.h"
#include "modules/global/service.h"
#include "modules/rpc.h"

enum
{
	// Used by warden.messageNetwork and warden.messageServer
	ERR_NO_GLOBAL_SERVICE = RPC::ERR_CUSTOM_START,

	// Used by warden.messageServer
	ERR_NO_SUCH_SERVER = RPC::ERR_CUSTOM_START + 1,

	// Used by warden.messageUser
	ERR_NO_SUCH_SOURCE = RPC::ERR_CUSTOM_START,
	ERR_NO_SUCH_TARGET = RPC::ERR_CUSTOM_START + 1,
};

class MessageNetworkRPCEvent final
	: public RPC::Event
{
public:
	MessageNetworkRPCEvent(Module *o)
		: RPC::Event(o, "warden.messageNetwork", 1)
	{
	}

	bool Run(RPC::ServiceInterface *iface, HTTP::Client *client, RPC::Request &request) override
	{
		if (!Global::service)
		{
			request.Error(ERR_NO_GLOBAL_SERVICE, "No global service");
			return true;
		}

		for (const auto &message : request.data)
			Global::service->SendSingle(Warden::ReplaceUnsafe(message));
		return true;
	}
};

class MessageServerRPCEvent final
	: public RPC::Event
{
public:
	MessageServerRPCEvent(Module *o)
		: RPC::Event(o, "warden.messageServer", 2)
	{
	}

	bool Run(RPC::ServiceInterface *iface, HTTP::Client *client, RPC::Request &request) override
	{
		if (!Global::service)
		{
			request.Error(ERR_NO_GLOBAL_SERVICE, "No global service");
			return true;
		}

		auto *s = Server::Find(request.data[0], true);
		if (!s)
		{
			request.Error(ERR_NO_SUCH_SERVER, "No such server");
			return true;
		}

		std::vector<Warden::string> messages(request.data.begin() + 1, request.data.end());
		for (const auto &message : messages)
			Global::service->SendSingle(Warden::ReplaceUnsafe(message), nullptr, nullptr, s);
		return true;
	}
};

class MessageUserRPCEvent final
	: public RPC::Event
{
public:
	MessageUserRPCEvent(Module *o)
		: RPC::Event(o, "warden.messageUser", 3)
	{
	}

	bool Run(RPC::ServiceInterface *iface, HTTP::Client *client, RPC::Request &request) override
	{
		auto *bi = BotInfo::Find(request.data[0], true);
		if (!bi)
		{
			request.Error(ERR_NO_SUCH_SOURCE, "No such source");
			return true;
		}

		auto *u = User::Find(request.data[1], true);
		if (!u)
		{
			request.Error(ERR_NO_SUCH_TARGET, "No such target");
			return true;
		}

		u->SendMessage(bi, Warden::ReplaceUnsafe(request.data[2]));
		return true;
	}
};

class ModuleRPCSystem final
	: public Module
{
private:
	MessageNetworkRPCEvent messagenetworkrpcevent;
	MessageServerRPCEvent messageserverrpcevent;
	MessageUserRPCEvent messageuserrpcevent;

public:
	ModuleRPCSystem(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, EXTRA | VENDOR)
		, messagenetworkrpcevent(this)
		, messageserverrpcevent(this)
		, messageuserrpcevent(this)
	{
	}
};

MODULE_INIT(ModuleRPCSystem)
