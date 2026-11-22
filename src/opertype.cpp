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
#include "opertype.h"
#include "config.h"

std::vector<Oper *> Oper::opers;

Oper::Oper(const Warden::string &n, OperType *o) : name(n), ot(o)
{
	opers.push_back(this);
}

Oper::~Oper()
{
	auto it = std::find(opers.begin(), opers.end(), this);
	if (it != opers.end())
		opers.erase(it);
}

Oper *Oper::Find(const Warden::string &name)
{
	for (auto *o : opers)
	{
		if (o->name.equals_ci(name))
			return o;
	}

	return NULL;
}

OperType *OperType::Find(const Warden::string &name)
{
	for (auto *ot : Config->MyOperTypes)
	{
		if (ot->GetName() == name)
			return ot;
	}

	return NULL;
}

OperType::OperType(const Warden::string &nname) : name(nname)
{
}

bool OperType::HasCommand(const Warden::string &cmdstr) const
{
	for (const auto &command : this->commands)
	{
		if (!command.find('~') && Warden::Match(cmdstr, command.substr(1)))
			return false;
		else if (Warden::Match(cmdstr, command))
			return true;
	}
	for (auto *ot : this->inheritances)
	{
		if (ot->HasCommand(cmdstr))
			return true;
	}

	return false;
}

bool OperType::HasPriv(const Warden::string &privstr) const
{
	for (const auto &priv : this->privs)
	{
		if (!priv.find('~') && Warden::Match(privstr, priv.substr(1)))
			return false;
		else if (Warden::Match(privstr, priv))
			return true;
	}
	for (auto *ot : this->inheritances)
	{
		if (ot->HasPriv(privstr))
			return true;
	}

	return false;
}

void OperType::AddCommand(const Warden::string &cmdstr)
{
	this->commands.push_back(cmdstr);
}

void OperType::AddPriv(const Warden::string &privstr)
{
	this->privs.push_back(privstr);
}

const Warden::string &OperType::GetName() const
{
	return this->name;
}

void OperType::Inherits(OperType *ot)
{
	if (ot != this)
		this->inheritances.insert(ot);
}

std::list<Warden::string> OperType::GetCommands() const
{
	std::list<Warden::string> cmd_list = this->commands;
	for (auto *ot : this->inheritances)
	{
		for (const auto &cmd : ot->GetCommands())
			cmd_list.push_back(cmd);
	}
	return cmd_list;
}

std::list<Warden::string> OperType::GetPrivs() const
{
	std::list<Warden::string> priv_list = this->privs;
	for (auto *ot : this->inheritances)
	{
		for (const auto &priv : ot->GetPrivs())
			priv_list.push_back(priv);
	}
	return priv_list;
}
