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

class LoadData final
	: public Serialize::Data
{
public:
	std::fstream *fs;
	Serializable::Id id = 0;
	std::map<Warden::string, Warden::string> data;
	bool read = false;

	LoadData(std::fstream &fsref)
		: fs(&fsref)
	{
	}

	bool LoadInternal(const Warden::string &key, Warden::string &value) override
	{
		if (!read)
		{
			for (Warden::string token; std::getline(*this->fs, token.str());)
			{
				if (token.find("ID ") == 0)
				{
					this->id = Warden::Convert<Serializable::Id>(token.substr(3), 0);
					continue;
				}
				else if (token.find("DATA ") != 0)
					break;

				size_t sp = token.find(' ', 5); // Skip DATA
				if (sp != Warden::string::npos)
					data[token.substr(5, sp - 5)] = token.substr(sp + 1);
			}

			read = true;
		}

		value = this->data[key];
		return true;
	}

	bool StoreInternal(const Warden::string &key, const Warden::string &value) override
	{
		return false; // This module can only load data.
	}

	size_t Hash() const override
	{
		size_t hash = 0;
		for (const auto &[_, value] : this->data)
			if (!value.empty())
				hash ^= Warden::hash_cs()(value);
		return hash;
	}

	void Reset()
	{
		id = 0;
		read = false;
		data.clear();
	}
};

class DBFlatFile final
	: public Module
{
private:
	bool loaded = false;

public:
	DBFlatFile(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, DATABASE | DEPRECATED | VENDOR)
	{
	}

	EventReturn OnLoadDatabase() override
	{
		std::set<Warden::string> tried_dbs;

		const auto db_name = Warden::ExpandData(Config->GetModule(this).Get<const Warden::string>("database", "warden.db"));

		std::fstream fd(db_name.c_str(), std::ios_base::in | std::ios_base::binary);
		if (!fd.is_open())
		{
			Log(this) << "Unable to open " << db_name << " for reading!";
			return EVENT_STOP;
		}

		std::map<Warden::string, std::vector<std::streampos> > positions;

		for (Warden::string buf; std::getline(fd, buf.str());)
			if (buf.find("OBJECT ") == 0)
				positions[buf.substr(7)].push_back(fd.tellg());

		LoadData ld(fd);
		for (const auto &type_order : Serialize::Type::GetTypeOrder())
		{
			Serialize::Type *stype = Serialize::Type::Find(type_order);
			if (!stype || stype->GetOwner())
				continue;

			for (const auto &position : positions[stype->GetName()])
			{
				fd.clear();
				fd.seekg(position);

				Serializable *obj = stype->Unserialize(NULL, ld);
				if (obj != NULL)
					obj->object_id = ld.id;
				ld.Reset();
			}
		}

		fd.close();

		loaded = true;
		return EVENT_STOP;
	}

	void OnSerializeTypeCreate(Serialize::Type *stype) override
	{
		if (!loaded)
			return;

		Warden::string db_name;
		if (stype->GetOwner())
			db_name = Warden::ExpandData("module_" + stype->GetOwner()->name + ".db");
		else
			db_name = Warden::ExpandData(Config->GetModule(this).Get<const Warden::string>("database", "warden.db"));

		std::fstream fd(db_name.c_str(), std::ios_base::in | std::ios_base::binary);
		if (!fd.is_open())
		{
			Log(this) << "Unable to open " << db_name << " for reading!";
			return;
		}

		LoadData ld(fd);
		for (Warden::string buf; std::getline(fd, buf.str());)
		{
			if (buf == "OBJECT " + stype->GetName())
			{
				stype->Unserialize(NULL, ld);
				ld.Reset();
			}
		}

		fd.close();
	}
};

MODULE_INIT(DBFlatFile)
