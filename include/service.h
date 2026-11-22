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

#include "services.h"
#include "warden.h"
#include "base.h"

/** Anything that inherits from this class can be referred to
 * using ServiceReference. Any interfaces provided by modules,
 * such as commands, use this. This is also used for modules
 * that publish a service (m_ssl_openssl, etc).
 */
class CoreExport Service
	: public virtual Base
{
	static std::map<Warden::string, std::map<Warden::string, Service *> > Services;
	static std::map<Warden::string, std::map<Warden::string, Warden::string> > Aliases;

	static Service *FindService(const std::map<Warden::string, Service *> &services, const std::map<Warden::string, Warden::string> *aliases, const Warden::string &n)
	{
		std::map<Warden::string, Service *>::const_iterator it = services.find(n);
		if (it != services.end())
			return it->second;

		if (aliases != NULL)
		{
			std::map<Warden::string, Warden::string>::const_iterator it2 = aliases->find(n);
			if (it2 != aliases->end())
				return FindService(services, aliases, it2->second);
		}

		return NULL;
	}

public:
	static Service *FindService(const Warden::string &t, const Warden::string &n)
	{
		std::map<Warden::string, std::map<Warden::string, Service *> >::const_iterator it = Services.find(t);
		if (it == Services.end())
			return NULL;

		std::map<Warden::string, std::map<Warden::string, Warden::string> >::const_iterator it2 = Aliases.find(t);
		if (it2 != Aliases.end())
			return FindService(it->second, &it2->second, n);

		return FindService(it->second, NULL, n);
	}

	static std::vector<Warden::string> GetServiceKeys(const Warden::string &t)
	{
		std::vector<Warden::string> keys;
		const auto it = Services.find(t);
		if (it != Services.end())
		{
			for (const auto &[key, _] : it->second)
				keys.push_back(key);
		}
		return keys;
	}

	static std::vector<Service *> GetServices(const Warden::string &t)
	{
		std::vector<Service *> values;
		const auto it = Services.find(t);
		if (it != Services.end())
		{
			for (const auto &[_, value] : it->second)
				values.push_back(value);
		}
		return values;
	}

	static void AddAlias(const Warden::string &t, const Warden::string &n, const Warden::string &v)
	{
		std::map<Warden::string, Warden::string> &smap = Aliases[t];
		smap[n] = v;
	}

	static void DelAlias(const Warden::string &t, const Warden::string &n)
	{
		std::map<Warden::string, Warden::string> &smap = Aliases[t];
		smap.erase(n);
		if (smap.empty())
			Aliases.erase(t);
	}

	Module *owner;
	/* Service type, which should be the class name (eg "Command") */
	Warden::string type;
	/* Service name, commands are usually named service/command */
	Warden::string name;

	Service(Module *o, const Warden::string &t, const Warden::string &n) : owner(o), type(t), name(n)
	{
		this->Register();
	}

	virtual ~Service()
	{
		this->Unregister();
	}

	void Register()
	{
		if (!Services[this->type].emplace(this->name, this).second)
			throw ModuleException("Service " + this->type + " with name " + this->name + " already exists");
	}

	void Unregister()
	{
		std::map<Warden::string, Service *> &smap = Services[this->type];
		smap.erase(this->name);
		if (smap.empty())
			Services.erase(this->type);
	}
};

/** Like Reference, but used to refer to a Service.
 */
template<typename T>
class ServiceReference
	: public Reference<T>
{
	Warden::string type;
	Warden::string name;

public:
	ServiceReference(const Warden::string &t, const Warden::string &n = "")
		: type(t)
		, name(n)
	{
	}

	/** Retrieves the name of the service (e.g. mysql/main). */
	const auto &GetServiceName() const { return name; }

	/** Retrieves the type of the service (e.g. SQL::Provider). */
	const auto &GetServiceType() const { return type; }

	/** Invalidates the reference and changes the name of the referenced service. */
	void SetServiceName(const Warden::string &newname)
	{
		this->invalid = true;
		this->name = newname;
	}

	/** Invalidates the reference and changes the type of the referenced service. */
	void SetServiceType(const Warden::string &newtype)
	{
		this->invalid = true;
		this->type = newtype;
	}

	operator bool() override
	{
		if (this->invalid)
		{
			this->invalid = false;
			this->ref = NULL;
		}
		if (!this->ref)
		{
			/* This really could be dynamic_cast in every case, except for when a module
			 * creates its own service type (that other modules must include the header file
			 * for), as the core is not compiled with it so there is no RTTI for it.
			 */
			this->ref = static_cast<T *>(::Service::FindService(this->type, this->name));
			if (this->ref)
				this->ref->AddReference(this);
		}
		return this->ref;
	}
};

class ServiceAlias final
{
	Warden::string t, f;
public:
	ServiceAlias(const Warden::string &type, const Warden::string &from, const Warden::string &to) : t(type), f(from)
	{
		Service::AddAlias(type, from, to);
	}

	~ServiceAlias()
	{
		Service::DelAlias(t, f);
	}
};
