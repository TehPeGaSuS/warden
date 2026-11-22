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

/// BEGIN CMAKE
/// find_package("SQLite3" REQUIRED)
/// target_link_libraries(${SO} PRIVATE SQLite::SQLite3)
/// END CMAKE

#include "module.h"
#include "modules/sql.h"
#include <sqlite3.h>

using namespace SQL;

/* SQLite3 API, based from InspIRCd */

/** A SQLite result
 */
class SQLiteResult final
	: public Result
{
public:
	SQLiteResult(unsigned int i, const Query &q, const Warden::string &fq) : Result(i, q, fq)
	{
	}

	SQLiteResult(const Query &q, const Warden::string &fq, const Warden::string &err) : Result(0, q, fq, err)
	{
	}

	void AddRow(const std::map<Warden::string, Warden::string> &data)
	{
		this->entries.push_back(data);
	}
};

/** A SQLite database, there can be multiple
 */
class SQLiteService final
	: public Provider
{
	std::map<Warden::string, std::set<Warden::string> > active_schema;

	Warden::string database;

	sqlite3 *sql = nullptr;

	Warden::string Escape(const Warden::string &query);

public:
	SQLiteService(Module *o, const Warden::string &n, const Warden::string &d);

	~SQLiteService();

	void Run(Interface *i, const Query &query) override;

	Result RunQuery(const Query &query) override;

	std::vector<Query> CreateTable(const Warden::string &table, const Data &data) override;

	Query BuildInsert(const Warden::string &table, Serializable::Id id, Data &data) override;

	Query GetTables(const Warden::string &prefix) override;

	Warden::string BuildQuery(const Query &q);

	Warden::string FromUnixtime(time_t) override;

	Warden::string GetColumnType(Serialize::DataType dt)
	{
		switch (dt)
		{
			case Serialize::DataType::BOOL:
				return "INTEGER";

			case Serialize::DataType::FLOAT:
				return "REAL";

			case Serialize::DataType::INT:
				return "INTEGER";

			case Serialize::DataType::TEXT:
				return "TEXT";

			// SQLite lacks support for 64-bit unsigned integers so we have to
			// store them as text columns instead.
			case Serialize::DataType::UINT:
				return "TEXT";
		}

		return "TEXT"; // Should never be reached
	}
};

class ModuleSQLite final
	: public Module
{
	/* SQL connections */
	std::map<Warden::string, SQLiteService *> SQLiteServices;
public:
	ModuleSQLite(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, EXTRA | VENDOR)
	{
		Log(this) << "Module was compiled against SQLite version " << SQLITE_VERSION << " and is running against version " << sqlite3_libversion();
	}

	~ModuleSQLite()
	{
		for (std::map<Warden::string, SQLiteService *>::iterator it = this->SQLiteServices.begin(); it != this->SQLiteServices.end(); ++it)
			delete it->second;
		SQLiteServices.clear();
	}

	void OnReload(Configuration::Conf &conf) override
	{
		const auto &config = conf.GetModule(this);

		for (std::map<Warden::string, SQLiteService *>::iterator it = this->SQLiteServices.begin(); it != this->SQLiteServices.end();)
		{
			const Warden::string &cname = it->first;
			SQLiteService *s = it->second;
			size_t i, num;
			++it;

			for (i = 0, num = config.CountBlock("sqlite"); i < num; ++i)
				if (config.GetBlock("sqlite", i).Get<const Warden::string>("name", "sqlite/main") == cname)
					break;

			if (i == num)
			{
				Log(LOG_NORMAL, "sqlite") << "SQLite: Removing server connection " << cname;

				delete s;
				this->SQLiteServices.erase(cname);
			}
		}

		for (const auto &[_,  block] : config.GetBlocks("sqlite"))
		{
			Warden::string connname = block.Get<const Warden::string>("name", "sqlite/main");

			if (this->SQLiteServices.find(connname) == this->SQLiteServices.end())
			{
				auto database = Warden::ExpandData(block.Get<const Warden::string>("database", "warden"));
				try
				{
					auto *ss = new SQLiteService(this, connname, database);
					this->SQLiteServices[connname] = ss;

					Log(LOG_NORMAL, "sqlite") << "SQLite: Successfully added database " << database;
				}
				catch (const SQL::Exception &ex)
				{
					Log(LOG_NORMAL, "sqlite") << "SQLite: " << ex.GetReason();
				}
			}
		}
	}
};

SQLiteService::SQLiteService(Module *o, const Warden::string &n, const Warden::string &d)
: Provider(o, n), database(d)
{
	int db = sqlite3_open_v2(database.c_str(), &this->sql, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, 0);
	if (db != SQLITE_OK)
	{
		Warden::string exstr = "Unable to open SQLite database " + database;
		if (this->sql)
		{
			exstr += ": ";
			exstr += sqlite3_errmsg(this->sql);
			sqlite3_close(this->sql);
		}
		throw SQL::Exception(exstr);
	}
}

SQLiteService::~SQLiteService()
{
	sqlite3_interrupt(this->sql);
	sqlite3_close(this->sql);
}

void SQLiteService::Run(Interface *i, const Query &query)
{
	Result res = this->RunQuery(query);
	if (!res.GetError().empty())
		i->OnError(res);
	else
		i->OnResult(res);
}

Result SQLiteService::RunQuery(const Query &query)
{
	Warden::string real_query = this->BuildQuery(query);
	sqlite3_stmt *stmt;
	int err = sqlite3_prepare_v2(this->sql, real_query.c_str(), real_query.length(), &stmt, NULL);
	if (err != SQLITE_OK)
		return SQLiteResult(query, real_query, sqlite3_errmsg(this->sql));

	std::vector<Warden::string> columns;
	int cols = sqlite3_column_count(stmt);
	columns.resize(cols);
	for (int i = 0; i < cols; ++i)
		columns[i] = sqlite3_column_name(stmt, i);

	SQLiteResult result(0, query, real_query);

	while ((err = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		std::map<Warden::string, Warden::string> items;
		for (int i = 0; i < cols; ++i)
		{
			const char *data = reinterpret_cast<const char *>(sqlite3_column_text(stmt, i));
			if (data && *data)
				items[columns[i]] = data;
		}
		result.AddRow(items);
	}

	result.id = sqlite3_last_insert_rowid(this->sql);

	sqlite3_finalize(stmt);

	if (err != SQLITE_DONE)
		return SQLiteResult(query, real_query, sqlite3_errmsg(this->sql));

	// GCC and clang disagree about whether this should be a move >:(
#ifdef __clang__
	return std::move(result);
#else
	return result;
#endif
}

std::vector<Query> SQLiteService::CreateTable(const Warden::string &table, const Data &data)
{
	std::vector<Query> queries;
	std::set<Warden::string> &known_cols = this->active_schema[table];

	if (known_cols.empty())
	{
		Log(LOG_DEBUG) << "sqlite: Fetching columns for " << table;

		Result columns = this->RunQuery("PRAGMA table_info(" + table + ")");
		for (int i = 0; i < columns.Rows(); ++i)
		{
			const Warden::string &column = columns.Get(i, "name");

			Log(LOG_DEBUG) << "sqlite: Column #" << i << " for " << table << ": " << column;
			known_cols.insert(column);
		}
	}

	if (known_cols.empty())
	{
		Warden::string query_text = "CREATE TABLE `" + table + "` (`id` INTEGER PRIMARY KEY, `timestamp` timestamp DEFAULT CURRENT_TIMESTAMP";

		for (const auto &[column, _] : data.data)
		{
			known_cols.insert(column);

			query_text += ", `" + column + "` " + GetColumnType(data.GetType(column));
		}

		query_text += ")";

		queries.push_back(query_text);

		query_text = "CREATE UNIQUE INDEX `" + table + "_id_idx` ON `" + table + "` (`id`)";
		queries.push_back(query_text);

		query_text = "CREATE INDEX `" + table + "_timestamp_idx` ON `" + table + "` (`timestamp`)";
		queries.push_back(query_text);

		query_text = "CREATE TRIGGER `" + table + "_trigger` AFTER UPDATE ON `" + table + "` FOR EACH ROW BEGIN UPDATE `" + table + "` SET `timestamp` = CURRENT_TIMESTAMP WHERE `id` = `old.id`; end;";
		queries.push_back(query_text);
	}
	else
	{
		for (const auto &[column, _] : data.data)
		{
			if (known_cols.count(column) > 0)
				continue;

			known_cols.insert(column);

			Warden::string query_text = "ALTER TABLE `" + table + "` ADD `" + column + "` " + GetColumnType(data.GetType(column));;

			queries.push_back(query_text);
		}
	}

	return queries;
}

Query SQLiteService::BuildInsert(const Warden::string &table, Serializable::Id id, Data &data)
{
	/* Empty columns not present in the data set */
	for (const auto &known_col : this->active_schema[table])
	{
		if (known_col != "id" && known_col != "timestamp" && data.data.count(known_col) == 0)
			data.data[known_col];
	}

	Warden::string query_text = "REPLACE INTO `" + table + "` (";
	if (id > 0)
		query_text += "`id`,";
	for (const auto &[field, _] : data.data)
		query_text += "`" + field + "`,";
	query_text.erase(query_text.length() - 1);
	query_text += ") VALUES (";
	if (id > 0)
		query_text += Warden::ToString(id) + ",";
	for (const auto &[field, _] : data.data)
		query_text += "@" + field + "@,";
	query_text.erase(query_text.length() - 1);
	query_text += ")";

	Query query(query_text);
	for (auto &[field, value] : data.data)
	{
		auto buf = value;
		auto escape = true;
		switch (data.GetType(field))
		{
			case Serialize::DataType::BOOL:
			case Serialize::DataType::FLOAT:
			case Serialize::DataType::INT:
			{
				if (buf.empty())
					buf = "0";
				escape = false;
				break;
			}

			case Serialize::DataType::TEXT:
			case Serialize::DataType::UINT:
			{
				if (buf.empty())
				{
					buf = "NULL";
					escape = false;
				}
				break;
			}
		}

		query.SetValue(field, buf, escape);
	}

	return query;
}

Query SQLiteService::GetTables(const Warden::string &prefix)
{
	return Query("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '" + prefix + "%';");
}

Warden::string SQLiteService::Escape(const Warden::string &query)
{
	char *e = sqlite3_mprintf("%q", query.c_str());
	Warden::string buffer = e;
	sqlite3_free(e);
	return buffer;
}

Warden::string SQLiteService::BuildQuery(const Query &q)
{
	Warden::string real_query = q.query;

	for (const auto &[name, value] : q.parameters)
		real_query = real_query.replace_all_cs("@" + name + "@", (value.escape ? ("'" + this->Escape(value.data) + "'") : value.data));

	return real_query;
}

Warden::string SQLiteService::FromUnixtime(time_t t)
{
	return "datetime('" + Warden::ToString(t) + "', 'unixepoch')";
}

MODULE_INIT(ModuleSQLite)
