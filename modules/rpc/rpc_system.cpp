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
#include "modules/rpc.h"

// TODO:
//
// * system.getCapabilities
// * system.methodHelp
// * system.methodSignature

class WardenDebugTypesRPCEvent final
	: public RPC::Event
{
public:
	WardenDebugTypesRPCEvent(Module *o)
		: RPC::Event(o, "warden.debugTypes")
	{
#if !DEBUG_BUILD
		Unregister();
#endif
	}

	bool Run(RPC::ServiceInterface *iface, HTTP::Client *client, RPC::Request &request) override
	{
		// For both the map type and array type we test that we can handle:
		//
		// * Arrays
		// * Maps
		// * Strings
		// * Null
		// * Boolean true
		// * Boolean false
		// * Doubles
		// * Signed integer that can fit into a 32-bit type.
		// * Signed integer that needs a 64-bit type.
		// * Unsigned integer that can fit into a 32-bit signed type.
		// * Unsigned integer that needs a 64-bit signed type.
		// * Unsigned integer that needs a 64-bit unsigned type.

		auto &root = request.Root();

		auto &array = root.ReplyArray("array");
		array.ReplyArray();
		array.ReplyMap();
		array.Reply("string");
		array.Reply(nullptr);
		array.Reply(true);
		array.Reply(false);
		array.Reply(42.42);
		array.Reply(int64_t(42));
		array.Reply(int64_t(INT32_MAX) + 42);
		array.Reply(uint64_t(42));
		array.Reply(uint64_t(INT32_MAX) + 42);
		array.Reply(uint64_t(INT64_MAX) + 42);

		root.ReplyMap("map");
		root.Reply("string", "string");
		root.Reply("null", nullptr);
		root.Reply("true", true);
		root.Reply("false", false);
		root.Reply("double", 42.42);
		root.Reply("int-small", int64_t(42));
		root.Reply("int-large", int64_t(INT32_MAX) + 42);
		root.Reply("uint-small", uint64_t(42));
		root.Reply("uint-medium", uint64_t(INT32_MAX) + 42);
		root.Reply("uint-large", uint64_t(INT64_MAX) + 42);

		return true;
	}
};

class SystemListMethodsRPCEvent final
	: public RPC::Event
{
public:
	SystemListMethodsRPCEvent(Module *o)
		: RPC::Event(o, "system.listMethods")
	{
	}

	bool Run(RPC::ServiceInterface *iface, HTTP::Client *client, RPC::Request &request) override
	{
		auto &root = request.Root<RPC::Array>();
		for (const auto &event : Service::GetServiceKeys(RPC_EVENT))
			root.Reply(event);
		return true;
	}
};

class ModuleRPCSystem final
	: public Module
{
private:
	WardenDebugTypesRPCEvent wardendebugtypesrpcevent;
	SystemListMethodsRPCEvent systemlistmethodsrpcevent;

public:
	ModuleRPCSystem(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, EXTRA | VENDOR)
		, wardendebugtypesrpcevent(this)
		, systemlistmethodsrpcevent(this)
	{
	}
};

MODULE_INIT(ModuleRPCSystem)
