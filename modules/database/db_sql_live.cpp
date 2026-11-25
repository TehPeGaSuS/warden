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
	, public SQL::Listener
{
private:
	/* PostgreSQL only: tables tell us about changes through LISTEN/NOTIFY, so
	 * types are read once and then kept up to date from the notifications
	 * instead of being polled on every lookup.
	 */
	bool notify = false;
	Provider *listening = nullptr;
	Warden::string listening_name;
	std::set<Warden::string> triggers;

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
		if (!init || !SQL)
			return false;
		this->CheckListen();
		return true;
	}

	Warden::string Channel() const
	{
		return this->prefix + "live";
	}

	/** Stops listening, if the provider we listen to still exists. */
	void StopListening()
	{
		if (this->listening)
		{
			ServiceReference<Provider> old("SQL::Provider", this->listening_name);
			if (old && *old == this->listening)
				old->Unlisten(this);
		}
		this->listening = nullptr;
		this->listening_name.clear();
	}

	/** Starts or stops listening when the SQL service changes. */
	void CheckListen()
	{
		Provider *provider = SQL ? *SQL : nullptr;
		if (provider == this->listening)
			return;

		this->StopListening();
		this->notify = false;
		this->triggers.clear();

		if (!provider || provider->GetDriver() != "postgresql")
			return;

		auto res = provider->RunQuery(Query("CREATE OR REPLACE FUNCTION warden_live_notify() RETURNS trigger LANGUAGE plpgsql AS $$ "
			"BEGIN "
				"IF TG_OP = 'DELETE' THEN "
					"PERFORM pg_notify(TG_ARGV[0], TG_TABLE_NAME || ' D ' || OLD.id); "
				"ELSE "
					"PERFORM pg_notify(TG_ARGV[0], TG_TABLE_NAME || ' U ' || NEW.id); "
				"END IF; "
				"RETURN NULL; "
			"END $$"));
		if (!res)
		{
			Log(this) << "Unable to create the notification function, falling back to polling: " << res.GetError();
			return;
		}

		if (provider->Listen(this->Channel(), this))
		{
			this->listening = provider;
			this->listening_name = provider->name;
			this->notify = true;
			Log(this) << "Using PostgreSQL notifications for live updates";
		}
	}

	/** Makes the table send a notification when a row changes. */
	void EnsureTrigger(const Warden::string &table)
	{
		if (!this->notify || this->triggers.count(table))
			return;

		const auto trigger = table + "_live";
		this->RunQuery("DROP TRIGGER IF EXISTS `" + trigger + "` ON `" + table + "`");
		auto res = this->RunQuery("CREATE TRIGGER `" + trigger + "` AFTER INSERT OR UPDATE OR DELETE ON `" + table + "` "
			"FOR EACH ROW EXECUTE FUNCTION warden_live_notify('" + this->Channel() + "')");
		if (res)
			this->triggers.insert(table);
	}

	/** Applies one database row to the object with that id.
	 * @return true if the row was marked for deletion (NULL timestamp).
	 */
	bool ApplyRow(Serialize::Type *obj, const std::map<Warden::string, Warden::string> &row)
	{
		auto idit = row.find("id");
		auto oid = idit == row.end() ? std::nullopt : Warden::TryConvert<Serializable::Id>(idit->second);
		if (!oid.has_value())
		{
			Log(LOG_DEBUG) << "Unable to convert id from " << obj->GetName();
			return false;
		}

		auto id = oid.value();
		auto tsit = row.find("timestamp");
		if (tsit == row.end() || tsit->second.empty())
		{
			auto it = obj->objects.find(id);
			if (it != obj->objects.end())
				delete it->second; // This also removes this object from the map
			return true;
		}

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
			}

			/* The Unserialize operation is destructive so rebuild the data for UpdateCache.
			 * Also the old data may contain columns that we don't use, so we reserialize the
			 * object to know for sure our cache is consistent
			 */
			Data data2;
			obj->Serialize(new_s, data2);
			new_s->UpdateCache(data2); /* We know this is the most up to date copy */
		}
		else
		{
			if (!s)
				this->RunQuery("UPDATE `" + GetTableName(obj) + "` SET `timestamp` = " + this->SQL->FromUnixtime(obj->GetTimestamp()) + " WHERE `id` = " + Warden::ToString(id));
			else
				delete s;
		}
		return false;
	}

	/** Reads the rows of a type that changed since it was last read, or all
	 * of them the first time.
	 * @param resync Read every row (other programs may change rows without
	 *               touching the timestamp) and remove objects whose rows are gone.
	 */
	void Poll(Serialize::Type *obj, bool resync)
	{
		Warden::string sql = Warden::Format("SELECT * from `%s`", GetTableName(obj).c_str());
		if (obj->GetTimestamp() && !resync)
			sql += Warden::Format(" WHERE (`timestamp` >= %s OR `timestamp` IS NULL)", this->SQL->FromUnixtime(obj->GetTimestamp()).c_str());

		Query query(sql);

		obj->UpdateTimestamp();

		Result res = this->RunQuery(query);

		bool clear_null = false;
		for (int i = 0; i < res.Rows(); ++i)
			clear_null |= this->ApplyRow(obj, res.Row(i));

		if (clear_null)
		{
			query = "DELETE FROM `" + GetTableName(obj) + "` WHERE `timestamp` IS NULL";
			this->RunQuery(query);
		}

		if (resync && res)
		{
			std::set<Serializable::Id> present;
			auto ids = this->RunQuery("SELECT `id` FROM `" + GetTableName(obj) + "`");
			for (int i = 0; i < ids.Rows(); ++i)
				present.insert(Warden::Convert<Serializable::Id>(ids.Get(i, "id"), 0));
			if (ids)
			{
				std::vector<Serializable *> gone;
				for (const auto &[id, s] : obj->objects)
					if (id > 0 && !present.count(id))
						gone.push_back(s);
				for (auto *s : gone)
					delete s;
			}
		}
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
				this->EnsureTrigger(GetTableName(s_type));

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

		// With notifications a type only has to be read once.
		if (this->notify && obj->GetTimestamp())
			return;

		this->Poll(obj, false);
		this->EnsureTrigger(GetTableName(obj));
	}

	void OnNotifications(const std::vector<Warden::string> &payloads) override
	{
		if (!this->CheckInit() || !this->notify)
			return;

		// Collect the changed ids per table: "<table> <U|D> <id>".
		std::map<Warden::string, std::set<Serializable::Id>> changed, deleted;
		for (const auto &payload : payloads)
		{
			spacesepstream sep(payload);
			Warden::string table, op, idstr;
			if (!sep.GetToken(table) || !sep.GetToken(op) || !sep.GetToken(idstr))
				continue;
			auto id = Warden::Convert<Serializable::Id>(idstr, 0);
			if (!id)
				continue;
			if (op == "D")
			{
				deleted[table].insert(id);
				changed[table].erase(id);
			}
			else
			{
				changed[table].insert(id);
				deleted[table].erase(id);
			}
		}

		// Apply them in type registration order so that, for example, a new
		// account exists before its nicks.
		for (const auto &tname : Serialize::Type::GetTypeOrder())
		{
			auto *obj = Serialize::Type::Find(tname);
			if (!obj || !obj->GetTimestamp())
				continue; // Not read yet; it is read in full when first used.

			const auto table = GetTableName(obj);
			for (const auto id : deleted[table])
			{
				auto it = obj->objects.find(id);
				if (it != obj->objects.end())
					delete it->second;
			}

			const auto &ids = changed[table];
			for (auto it = ids.begin(); it != ids.end();)
			{
				Warden::string list;
				std::set<Serializable::Id> asked;
				for (size_t n = 0; it != ids.end() && n < 500; ++it, ++n)
				{
					list += (list.empty() ? "" : ",") + Warden::ToString(*it);
					asked.insert(*it);
				}

				auto res = this->RunQuery("SELECT * FROM `" + table + "` WHERE `id` IN (" + list + ")");
				if (!res)
					continue;

				bool clear_null = false;
				for (int i = 0; i < res.Rows(); ++i)
				{
					asked.erase(Warden::Convert<Serializable::Id>(res.Get(i, "id"), 0));
					clear_null |= this->ApplyRow(obj, res.Row(i));
				}
				if (clear_null)
					this->RunQuery("DELETE FROM `" + table + "` WHERE `timestamp` IS NULL");

				// Rows that are gone by now were deleted after the change.
				for (const auto id : asked)
				{
					auto oit = obj->objects.find(id);
					if (oit != obj->objects.end())
						delete oit->second;
				}
			}
		}
	}

	void OnListenResync() override
	{
		if (!this->CheckInit() || !this->notify)
			return;

		Log(this) << "Reading changes missed while the notification connection was down";
		for (const auto &tname : Serialize::Type::GetTypeOrder())
		{
			auto *obj = Serialize::Type::Find(tname);
			if (obj && obj->GetTimestamp())
				this->Poll(obj, true);
		}
	}

	~DBMySQL()
	{
		this->StopListening();
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
