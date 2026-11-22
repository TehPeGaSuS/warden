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
#include "modules/sql.h"

using namespace SQL;

class DBMySQL final
	: public Module
	, public Pipe
{
private:
	Warden::string prefix;
	// Whether the default prefix is used, so Anope's tables may be renamed.
	bool migrate = false;
	ServiceReference<Provider> SQL;
	time_t lastwarn;
	bool ro;
	bool init;
	std::set<Serializable *> updated_items;

	bool CheckSQL()
	{
		if (SQL)
		{
			if (Warden::ReadOnly && this->ro)
			{
				Warden::ReadOnly = this->ro = false;
				Log() << "Found SQL again, going out of readonly mode...";
			}

			return true;
		}
		else
		{
			if (Warden::CurTime - Config->GetBlock("options").Get<time_t>("updatetimeout", "2m") > lastwarn)
			{
				Log() << "Unable to locate SQL reference, going to readonly...";
				Warden::ReadOnly = this->ro = true;
				this->lastwarn = Warden::CurTime;
			}

			return false;
		}
	}

	bool CheckInit()
	{
		return init && SQL;
	}

	Warden::string GetTableName(Serialize::Type *s_type)
	{
		return this->prefix + s_type->GetName();
	}

	Result RunQuery(const Query &query)
	{
		if (this->CheckSQL())
		{
			Result res = SQL->RunQuery(query);
			if (!res.GetError().empty())
				Log(LOG_DEBUG) << "SQL-live got error " << res.GetError() << " for " + res.finished_query;
			else
				Log(LOG_DEBUG) << "SQL-live got " << res.Rows() << " rows for " << res.finished_query;
			return res;
		}
		throw SQL::Exception("No SQL!");
	}

public:
	DBMySQL(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, DATABASE | VENDOR)
		, SQL("SQL::Provider")
	{
		this->lastwarn = 0;
		this->ro = false;
		this->init = false;


		if (ModuleManager::FindFirstOf(DATABASE) != this)
			throw ModuleException("If db_sql_live is loaded it must be the first database module loaded.");
	}

	void OnNotify() override
	{
		if (!this->CheckInit())
			return;

		std::set<Serializable *> items;
		std::swap(this->updated_items, items);

		for (auto *obj : items)
		{
			if (obj && this->SQL)
			{
				if (!obj->ShouldCommit())
				{
					OnSerializableDestruct(obj);
					continue; // Non-committable object.
				}

				Serialize::Type *s_type = obj->GetSerializableType();
				if (!s_type)
					continue;

				Data data;
				s_type->Serialize(obj, data);

				if (obj->IsCached(data))
					continue;

				obj->UpdateCache(data);

				auto create = this->SQL->CreateTable(GetTableName(s_type), data);
				for (const auto &query : create)
					this->RunQuery(query);

				auto res = this->RunQuery(this->SQL->BuildInsert(GetTableName(s_type), obj->object_id, data));
				if (res.GetID() && obj->object_id != res.GetID())
				{
					/* In this case obj is new, so place it into the object map */
					obj->object_id = res.GetID();
					s_type->objects[obj->object_id] = obj;
				}
			}
		}
	}

	EventReturn OnLoadDatabase() override
	{
		if (this->migrate && SQL)
			SQL::MigrateAnopeTables(*SQL, this->name);
		init = true;
		return EVENT_STOP;
	}

	void OnShutdown() override
	{
		init = false;
	}

	void OnRestart() override
	{
		init = false;
	}

	void OnReload(Configuration::Conf &conf) override
	{
		const auto &block = conf.GetModule(this);

		this->SQL.SetServiceName(block.Get<const Warden::string>("engine"));
		this->prefix = block.Get<const Warden::string>("prefix");
		this->migrate = this->prefix.empty();
		if (this->migrate)
			this->prefix = "warden21_";
	}

	void OnSerializableConstruct(Serializable *obj) override
	{
		if (!this->CheckInit())
			return;
		obj->UpdateTS();
		this->updated_items.insert(obj);
		this->Notify();
	}

	void OnSerializableDestruct(Serializable *obj) override
	{
		if (!this->CheckInit())
			return;
		Serialize::Type *s_type = obj->GetSerializableType();
		if (s_type)
		{
			if (obj->object_id > 0)
				this->RunQuery("DELETE FROM `" + GetTableName(s_type) + "` WHERE `id` = " + Warden::ToString(obj->object_id));
			s_type->objects.erase(obj->object_id);
		}
		this->updated_items.erase(obj);
	}

	void OnSerializeTypeCheck(Serialize::Type *obj) override
	{
		if (!this->CheckInit() || obj->GetTimestamp() == Warden::CurTime)
			return;

		Warden::string sql = Warden::Format("SELECT * from `%s`", GetTableName(obj).c_str());
		if (obj->GetTimestamp())
			sql += Warden::Format(" WHERE (`timestamp` >= %s OR `timestamp` IS NULL)", this->SQL->FromUnixtime(obj->GetTimestamp()).c_str());

		Query query(sql);

		obj->UpdateTimestamp();

		Result res = this->RunQuery(query);

		bool clear_null = false;
		for (int i = 0; i < res.Rows(); ++i)
		{
			const std::map<Warden::string, Warden::string> &row = res.Row(i);



			auto oid = Warden::TryConvert<Serializable::Id>(res.Get(i, "id"));
			if (!oid.has_value())
			{
				Log(LOG_DEBUG) << "Unable to convert id from " << obj->GetName();
				continue;
			}

			auto id = oid.value();
			if (res.Get(i, "timestamp").empty())
			{
				clear_null = true;
				auto it = obj->objects.find(id);
				if (it != obj->objects.end())
					delete it->second; // This also removes this object from the map
			}
			else
			{
				Data data;

				for (const auto &[key, value] : row)
					data.StoreInternal(key, value);

				Serializable *s = NULL;
				auto it = obj->objects.find(id);
				if (it != obj->objects.end())
					s = it->second;

				Serializable *new_s = obj->Unserialize(s, data);
				if (new_s)
				{
					// If s == new_s then s->object_id == new_s->object_id
					if (s != new_s)
					{
						new_s->object_id = id;
						obj->objects[id] = new_s;

						/* The Unserialize operation is destructive so rebuild the data for UpdateCache.
						 * Also the old data may contain columns that we don't use, so we reserialize the
						 * object to know for sure our cache is consistent
						 */

						Data data2;
						obj->Serialize(new_s, data2);
						new_s->UpdateCache(data2); /* We know this is the most up to date copy */
					}
				}
				else
				{
					if (!s)
						this->RunQuery("UPDATE `" + GetTableName(obj) + "` SET `timestamp` = " + this->SQL->FromUnixtime(obj->GetTimestamp()) + " WHERE `id` = " + Warden::ToString(id));
					else
						delete s;
				}
			}
		}

		if (clear_null)
		{
			query = "DELETE FROM `" + GetTableName(obj) + "` WHERE `timestamp` IS NULL";
			this->RunQuery(query);
		}
	}

	void OnSerializableUpdate(Serializable *obj) override
	{
		if (!this->CheckInit() || obj->IsTSCached())
			return;
		obj->UpdateTS();
		this->updated_items.insert(obj);
		this->Notify();
	}
};

MODULE_INIT(DBMySQL)
