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

#include "encryption.h"
#include "httpd.h"

#include <variant>

namespace RPC
{
	class Array;
	class Event;
	class Map;
	class Request;
	class ServiceInterface;
	struct Token;
	class Value;

	/** Represents possible types of RPC value. */
	using ValueUnion = std::variant<Array, Map, Warden::string, std::nullptr_t, bool, double, int64_t, uint64_t>;

	/** Represents standard RPC errors from the JSON-RPC specification. */
	enum Error
		: int64_t
	{
		ERR_CUSTOM_END       = -32000,
		ERR_CUSTOM_START     = -32099,
		ERR_PARSE_ERROR      = -32700,
		ERR_INVALID_REQUEST  = -32600,
		ERR_METHOD_NOT_FOUND = -32601,
		ERR_INVALID_PARAMS   = -32602,
	};
}

class RPC::Array final
{
private:
	std::vector<Value> replies;

public:
	/** Retrieves the list of RPC replies. */
	inline const auto &GetReplies() const { return this->replies; }

	template <typename T>
	inline Array &Reply(const T &t)
	{
		this->replies.emplace_back(RPC::Value(t));
		return *this;
	}

	inline Array &ReplyArray();

	inline Map &ReplyMap();
};

class RPC::Map final
{
private:
	Warden::map<Value> replies;

public:
	/** Retrieves the list of RPC replies. */
	inline const auto &GetReplies() const { return this->replies; }

	template <typename T>
	inline Map &Reply(const Warden::string &key, const T &t)
	{
		this->replies.emplace(key, RPC::Value(t));
		return *this;
	}

	inline Array &ReplyArray(const Warden::string &key);

	inline Map &ReplyMap(const Warden::string &key);
};

class RPC::Value final
{
private:
	RPC::ValueUnion value;

public:
	explicit Value(const ValueUnion &v)
		: value(v)
	{
	}

	explicit Value(const Array &a)
		: value(a)
	{
	}

	explicit Value(const Map &m)
		: value(m)
	{
	}

	explicit Value(std::nullptr_t)
		: value(nullptr)
	{
	}

	explicit Value(bool b)
		: value(b)
	{
	}

	Value(double d)
		: value(d)
	{
	}

	Value(int64_t i)
		: value(i)
	{
	}

	Value(uint64_t u)
		: value(u)
	{
	}

	template <typename T>
	Value(const T &t)
		: value(Warden::ToString(t))
	{
	}

	inline auto &Get() { return this->value; }

	inline const auto &Get() const { return this->value; }
};

class RPC::Request final
{
private:
	std::optional<std::pair<int64_t, Warden::string>> error;
	std::optional<Value> root;

public:
	Warden::string name;
	Warden::string id;
	std::deque<Warden::string> data;
	HTTP::Reply &reply;

	Request(HTTP::Reply &r)
		: reply(r)
	{
	}

	inline void Error(uint64_t errcode, const Warden::string &errstr)
	{
		this->error.emplace(errcode, errstr);
	}

	template<typename T = Map>
	inline T &Root();

	inline const auto &GetError() const { return this->error; }

	inline const auto &GetRoot() const { return this->root; }
};

#define RPC_EVENT "RPC::Event"

namespace RPC
{
	/** Maps a deprecated Anope method name (anope.listUsers) to its Warden
	 * name (warden.listUsers) so existing RPC clients keep working.
	 */
	inline Warden::string CanonicalMethod(const Warden::string &method)
	{
		if (method.compare(0, 6, "anope.", 6) == 0)
			return "warden." + method.substr(6);
		return method;
	}

	/** The other name of a method: warden.X <-> anope.X (empty if none). */
	inline Warden::string LegacyMethod(const Warden::string &method)
	{
		if (method.compare(0, 7, "warden.", 7) == 0)
			return "anope." + method.substr(7);
		return "";
	}
}

class RPC::Event
	: public Service
{
private:
	size_t minparams;

protected:
	Event(Module *o, const Warden::string &e, size_t mp = 0)
		: Service(o, RPC_EVENT, e)
		, minparams(mp)
	{
	}

public:
	virtual ~Event() = default;

	const auto &GetMinParams() const { return minparams; }

	virtual bool Run(ServiceInterface *iface, HTTP::Client *client, Request &request) = 0;
};

struct RPC::Token final
{
	std::vector<Warden::string> methods;
	Warden::string token;
	Warden::string token_hash;
};

class RPC::ServiceInterface
	: public Service
{
private:
	bool CompareToken(const RPC::Token &token, const Warden::string &rawtoken) const
	{
		if (token.token_hash.empty())
			return token.token.equals_cs(rawtoken); // Plaintext token.

		auto *service = Service::FindService("Encryption::Provider", token.token_hash);
		if (!service)
			return false; // Malformed hash.

		auto *hashprov = static_cast<Encryption::Provider *>(service);
		return hashprov->Compare(token.token, rawtoken);
	}

public:
	std::vector<Token> tokens;

	ServiceInterface(Module *creator)
		: Service(creator, "RPC::ServiceInterface", "rpc")
	{
	}

	bool CanExecute(const Warden::string &header, const Warden::string &method) const
	{
		if (header.compare(0, 7, "Bearer ", 7) != 0)
			return false; // No token provided.

		auto rawtoken = Warden::B64Decode(header.substr(7));
		for (const auto &token : tokens)
		{
			if (!CompareToken(token, rawtoken))
				continue; // No valid token.

			// Tokens from an Anope config may still list anope.* methods.
			const auto legacy = RPC::LegacyMethod(method);
			const auto matches = [&method, &legacy](const Warden::string &g) {
				return Warden::Match(method, g) || (!legacy.empty() && Warden::Match(legacy, g));
			};
			for (const auto &glob : token.methods)
			{
				if (glob[0] == '~' && matches(glob.substr(1)))
					return false; // Negative match.

				if (matches(glob))
					return true; // Positive match.
			}
		}
		return false; // No match.
	}

	virtual void Reply(Request &request) = 0;
};

inline RPC::Array &RPC::Array::ReplyArray()
{
	auto &reply = this->replies.emplace_back(RPC::Array());
	return std::get<RPC::Array>(reply.Get());
}

inline RPC::Map &RPC::Array::ReplyMap()
{
	auto &reply = this->replies.emplace_back(RPC::Map());
	return std::get<RPC::Map>(reply.Get());
}

inline RPC::Array &RPC::Map::ReplyArray(const Warden::string &key)
{
	auto it = this->replies.emplace(key, RPC::Array());
	return std::get<RPC::Array>(it.first->second.Get());
}

inline RPC::Map &RPC::Map::ReplyMap(const Warden::string &key)
{
	auto it = this->replies.emplace(key, RPC::Map());
	return std::get<RPC::Map>(it.first->second.Get());
}

template<typename T>
inline T &RPC::Request::Root()
{
	if (!this->root.has_value())
		this->root = RPC::Value(T());
	return std::get<T>(this->root.value().Get());
}
