// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2026 Warden Contributors
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// SPDX-License-Identifier: GPL-2.0-only

/// BEGIN CMAKE
/// if(WIN32)
///   find_package("PostgreSQL" REQUIRED)
///   target_link_libraries(${SO} PRIVATE "PostgreSQL::PostgreSQL")
/// else()
///   pkg_search_module("LIBPQ" IMPORTED_TARGET REQUIRED "libpq")
///   target_link_libraries(${SO} PRIVATE PkgConfig::LIBPQ)
/// endif()
/// END CMAKE

#include "module.h"
#include "modules/sql.h"

#include <libpq-fe.h>

#include <atomic>
#include <condition_variable>
#include <mutex>

using namespace SQL;

/** Non blocking threaded PostgreSQL API, built the same way as the mysql module.
 *
 * One thread runs the blocking libpq calls. Modules queue queries for it and
 * the results come back to the main thread through a Pipe.
 *
 * Queries in Warden quote identifiers with backticks, which is MySQL syntax.
 * This module turns them into double quotes (outside string literals) before
 * sending a query, so the same query text works on every backend.
 */

class PostgreSQLService;

/** Watches the listening connection's socket for notifications. */
class NotifySocket final
	: public Socket
{
	PostgreSQLService *service;

public:
	NotifySocket(PostgreSQLService *s, int fd) : Socket(fd), service(s) { }

	bool ProcessRead() override;

	bool ProcessWrite() override { return true; }

	void ProcessError() override;
};

/** Tries to bring a lost listening connection back. */
class ListenReconnectTimer final
	: public Timer
{
	PostgreSQLService *service;

public:
	ListenReconnectTimer(Module *m, PostgreSQLService *s) : Timer(m, 5), service(s) { }

	bool Tick() override;
};

struct QueryRequest final
{
	PostgreSQLService *service;
	Interface *sqlinterface;
	Query query;

	QueryRequest(PostgreSQLService *s, Interface *i, const Query &q) : service(s), sqlinterface(i), query(q) { }
};

struct QueryResult final
{
	Interface *sqlinterface;
	Result result;

	QueryResult(Interface *i, Result &r) : sqlinterface(i), result(r) { }
};

class PostgreSQLResult final
	: public Result
{
public:
	PostgreSQLResult(unsigned int i, const Query &q, const Warden::string &fq, PGresult *res) : Result(i, q, fq)
	{
		if (!res || PQresultStatus(res) != PGRES_TUPLES_OK)
			return;

		const int rows = PQntuples(res);
		const int cols = PQnfields(res);
		for (int row = 0; row < rows; ++row)
		{
			std::map<Warden::string, Warden::string> items;
			for (int col = 0; col < cols; ++col)
			{
				const char *name = PQfname(res, col);
				items[name ? name : ""] = PQgetisnull(res, row, col) ? "" : PQgetvalue(res, row, col);
			}
			this->entries.push_back(items);
		}
	}

	PostgreSQLResult(const Query &q, const Warden::string &fq, const Warden::string &err) : Result(0, q, fq, err)
	{
	}
};

class PostgreSQLService final
	: public Provider
{
	std::map<Warden::string, std::set<Warden::string>> active_schema;

	/* The highest id each table's id sequence is known to be at. Rows written
	 * with an explicit id do not move the sequence, so it is moved by hand.
	 */
	std::map<Warden::string, Serializable::Id> sequence_max;

	Warden::string conninfo;
	Warden::string display;

	PGconn *sql = nullptr;

	/* The backend process of the query connection. Notifications it causes
	 * are not passed on to listeners.
	 */
	std::atomic<int> backend_pid = 0;

	/* A second connection, used only for LISTEN. */
	PGconn *listen_conn = nullptr;
	NotifySocket *listen_socket = nullptr;
	ListenReconnectTimer *listen_timer = nullptr;
	std::map<SQL::Listener *, Warden::string> listeners;

	bool ConnectListener();
	void DropListener();

	/** Escape a string. The lock must be held. */
	Warden::string Escape(const Warden::string &str);

	/** Runs a query, the lock must be held. */
	Result Execute(const Query &query, const Warden::string &real_query);

public:
	std::mutex Lock;

	PostgreSQLService(Module *o, const Warden::string &n, const Warden::string &ci, const Warden::string &disp);

	~PostgreSQLService();

	void Run(Interface *i, const Query &query) override;

	Result RunQuery(const Query &query) override;

	std::vector<Query> CreateTable(const Warden::string &table, const Data &data) override;

	Query BuildInsert(const Warden::string &table, Serializable::Id id, Data &data) override;

	Query GetTables(const Warden::string &prefix) override;

	Warden::string FromUnixtime(time_t) override;

	Warden::string GetDriver() const override { return "postgresql"; }

	bool Listen(const Warden::string &channel, SQL::Listener *listener) override;

	void Unlisten(SQL::Listener *listener) override;

	/** Reads waiting notifications and passes them on. */
	bool ReadNotifications();

	/** The listening connection failed. */
	void ListenFailed();

	/** Called by the reconnect timer. */
	bool RetryListener();

	void Connect();

	bool CheckConnection();

	Warden::string BuildQuery(const Query &q);

	static const char *GetColumnType(Serialize::DataType dt)
	{
		switch (dt)
		{
			case Serialize::DataType::BOOL:
				return "SMALLINT";
			case Serialize::DataType::FLOAT:
				return "DOUBLE PRECISION";
			case Serialize::DataType::INT:
				return "BIGINT";
			case Serialize::DataType::TEXT:
				return "TEXT";
			case Serialize::DataType::UINT:
				return "NUMERIC(20)";
		}
		return "TEXT"; // Should never be reached
	}

	static Warden::string GetColumn(Serialize::DataType dt)
	{
		if (dt == Serialize::DataType::TEXT)
			return "TEXT NULL DEFAULT NULL";
		return Warden::Format("%s NOT NULL DEFAULT %s", GetColumnType(dt), dt == Serialize::DataType::FLOAT ? "0.0" : "0");
	}
};

class DispatcherThread final
	: public Thread
{
public:
	std::condition_variable_any condvar;
	std::mutex mutex;

	DispatcherThread() : Thread() { }

	void Run() override;
};

class ModulePostgreSQL;
static ModulePostgreSQL *me;

class ModulePostgreSQL final
	: public Module
	, public Pipe
{
	std::map<Warden::string, PostgreSQLService *> services;

public:
	std::deque<QueryRequest> QueryRequests;
	std::deque<QueryResult> FinishedRequests;
	DispatcherThread *DThread;

	ModulePostgreSQL(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, EXTRA | VENDOR)
	{
		me = this;

		DThread = new DispatcherThread();
		DThread->Start();

		const int version = PQlibVersion();
		Log(this) << "Module is running against PostgreSQL client library " << (version / 10000) << "." << (version % 10000);
	}

	~ModulePostgreSQL()
	{
		for (const auto &[_, service] : this->services)
			delete service;
		this->services.clear();

		DThread->SetExitState();
		DThread->condvar.notify_all();
		DThread->Join();
		delete DThread;
	}

	void OnReload(Configuration::Conf &conf) override
	{
		const auto &config = conf.GetModule(this);

		for (auto it = this->services.begin(); it != this->services.end();)
		{
			const Warden::string cname = it->first;
			PostgreSQLService *s = it->second;
			++it;

			size_t i;
			for (i = 0; i < config.CountBlock("postgresql"); ++i)
				if (config.GetBlock("postgresql", i).Get<const Warden::string>("name", "postgresql/main") == cname)
					break;

			if (i == config.CountBlock("postgresql"))
			{
				Log(LOG_NORMAL, "postgresql") << "PostgreSQL: Removing server connection " << cname;
				delete s;
				this->services.erase(cname);
			}
		}

		for (const auto &[_, block] : config.GetBlocks("postgresql"))
		{
			const auto &connname = block.Get<const Warden::string>("name", "postgresql/main");
			if (this->services.count(connname))
				continue;

			const auto &database = block.Get<const Warden::string>("database", "warden");
			const auto &server = block.Get<const Warden::string>("server", "127.0.0.1");
			const auto &user = block.Get<const Warden::string>("username", "warden");
			const auto &password = block.Get<const Warden::string>("password");
			const auto port = block.Get<unsigned int>("port", "5432");
			const auto &socket = block.Get<const Warden::string>("socket");
			const auto &sslmode = block.Get<const Warden::string>("sslmode", "prefer");

			// libpq connects to a Unix socket when the host is a directory.
			const auto &host = socket.empty() ? server : socket;

			auto quote = [](const Warden::string &value) {
				Warden::string out = "'";
				for (const auto chr : value)
				{
					if (chr == '\'' || chr == '\\')
						out.push_back('\\');
					out.push_back(chr);
				}
				return out + "'";
			};

			auto conninfo = "host=" + quote(host) + " port=" + Warden::ToString(port) + " dbname=" + quote(database)
				+ " user=" + quote(user) + " sslmode=" + quote(sslmode) + " connect_timeout=5 application_name='Warden'";
			if (!password.empty())
				conninfo += " password=" + quote(password);

			const auto display = socket.empty() ? server + ":" + Warden::ToString(port) : socket;
			try
			{
				auto *ss = new PostgreSQLService(this, connname, conninfo, display);
				this->services.emplace(connname, ss);
				Log(LOG_NORMAL, "postgresql") << "PostgreSQL: Successfully connected to server " << connname << " (" << display << ")";
			}
			catch (const SQL::Exception &ex)
			{
				Log(LOG_NORMAL, "postgresql") << "PostgreSQL: " << ex.GetReason();
			}
		}
	}

	void OnModuleUnload(User *, Module *m) override
	{
		this->DThread->mutex.lock();

		for (unsigned i = this->QueryRequests.size(); i > 0; --i)
		{
			QueryRequest &r = this->QueryRequests[i - 1];

			if (r.sqlinterface && r.sqlinterface->owner == m)
			{
				if (i == 1)
				{
					r.service->Lock.lock();
					r.service->Lock.unlock();
				}

				this->QueryRequests.erase(this->QueryRequests.begin() + i - 1);
			}
		}

		this->DThread->mutex.unlock();

		this->OnNotify();
	}

	void OnNotify() override
	{
		this->DThread->mutex.lock();
		std::deque<QueryResult> finishedRequests = this->FinishedRequests;
		this->FinishedRequests.clear();
		this->DThread->mutex.unlock();

		for (const auto &qr : finishedRequests)
		{
			if (!qr.sqlinterface)
				throw SQL::Exception("NULL qr.sqlinterface in PostgreSQL OnNotify() ?");

			if (qr.result.GetError().empty())
				qr.sqlinterface->OnResult(qr.result);
			else
				qr.sqlinterface->OnError(qr.result);
		}
	}
};

PostgreSQLService::PostgreSQLService(Module *o, const Warden::string &n, const Warden::string &ci, const Warden::string &disp)
	: Provider(o, n)
	, conninfo(ci)
	, display(disp)
{
	Connect();
}

PostgreSQLService::~PostgreSQLService()
{
	this->DropListener();
	delete this->listen_timer;
	this->listen_timer = nullptr;

	me->DThread->mutex.lock();
	this->Lock.lock();
	if (this->sql)
		PQfinish(this->sql);
	this->sql = nullptr;

	for (unsigned i = me->QueryRequests.size(); i > 0; --i)
	{
		QueryRequest &r = me->QueryRequests[i - 1];

		if (r.service == this)
		{
			if (r.sqlinterface)
				r.sqlinterface->OnError(Result(0, r.query, "SQL Interface is going away"));
			me->QueryRequests.erase(me->QueryRequests.begin() + i - 1);
		}
	}
	this->Lock.unlock();
	me->DThread->mutex.unlock();
}

void PostgreSQLService::Run(Interface *i, const Query &query)
{
	me->DThread->mutex.lock();
	me->QueryRequests.push_back(QueryRequest(this, i, query));
	me->DThread->mutex.unlock();
	me->DThread->condvar.notify_all();
}

Result PostgreSQLService::Execute(const Query &query, const Warden::string &real_query)
{
	PGresult *res = PQexec(this->sql, real_query.c_str());
	const auto status = res ? PQresultStatus(res) : PGRES_FATAL_ERROR;
	if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK)
	{
		Warden::string error = res ? PQresultErrorMessage(res) : PQerrorMessage(this->sql);
		error.trim();
		if (res)
			PQclear(res);
		return PostgreSQLResult(query, real_query, error);
	}

	// An INSERT ... RETURNING "id" tells us the id of the new row.
	unsigned int id = 0;
	if (status == PGRES_TUPLES_OK && PQntuples(res) == 1 && PQnfields(res) == 1)
	{
		const char *name = PQfname(res, 0);
		if (name && !strcmp(name, "warden_insert_id") && !PQgetisnull(res, 0, 0))
			id = Warden::Convert<unsigned int>(PQgetvalue(res, 0, 0), 0);
	}

	PostgreSQLResult result(id, query, real_query, res);
	PQclear(res);
	return result;
}

Result PostgreSQLService::RunQuery(const Query &query)
{
	std::lock_guard<std::mutex> lock(this->Lock);

	if (!this->CheckConnection())
		return PostgreSQLResult(query, query.query, this->sql ? PQerrorMessage(this->sql) : "not connected");

	return this->Execute(query, this->BuildQuery(query));
}

std::vector<Query> PostgreSQLService::CreateTable(const Warden::string &table, const Data &data)
{
	std::vector<Query> queries;
	std::set<Warden::string> &known_cols = this->active_schema[table];

	if (known_cols.empty())
	{
		Log(LOG_DEBUG) << "postgresql: Fetching columns for " << table;

		Query colquery("SELECT `column_name`, `data_type`, `numeric_precision` FROM `information_schema`.`columns` WHERE `table_schema` = current_schema() AND `table_name` = @table@");
		colquery.SetValue("table", table);
		Result columns = this->RunQuery(colquery);
		for (int i = 0; i < columns.Rows(); ++i)
		{
			const auto column = columns.Get(i, "column_name");
			if (column == "id" || column == "timestamp")
				continue;

			known_cols.insert(column);
			if (data.data.count(column) == 0)
				continue;

			// Change the column type if the data type changed. Values that do
			// not convert become the default.
			const auto stype = data.GetType(column);
			Warden::string want = GetColumnType(stype);
			want = want.lower();
			auto have = columns.Get(i, "data_type").lower();
			if (have == "numeric")
				have = "numeric(" + columns.Get(i, "numeric_precision") + ")";
			if (have == want)
				continue;

			Log(LOG_DEBUG) << "postgresql: Updating the type of " << column << " from " << have << " to " << want;
			auto res = this->RunQuery(Warden::Format("ALTER TABLE `%s` ADD COLUMN `%s_new` %s", table.c_str(), column.c_str(), GetColumn(stype).c_str()));
			if (res)
			{
				// Copy what converts cleanly, the rest keeps the default.
				Warden::string update = "UPDATE `" + table + "` SET `" + column + "_new` = `" + column + "`::" + GetColumnType(stype);
				if (stype != Serialize::DataType::TEXT)
					update += " WHERE `" + column + "`::text ~ '^-?[0-9]+(\\.[0-9]+)?$'";
				res = this->RunQuery(update);
			}
			if (res)
				res = this->RunQuery(Warden::Format("ALTER TABLE `%s` DROP COLUMN `%s`", table.c_str(), column.c_str()));
			if (res)
				res = this->RunQuery(Warden::Format("ALTER TABLE `%s` RENAME COLUMN `%s_new` TO `%s`", table.c_str(), column.c_str(), column.c_str()));
			if (!res)
				Log(LOG_DEBUG) << "postgresql: Failed to migrate the " << column << " column: " << res.GetError();
		}

		if (columns.Rows() > 0)
		{
			// Start the id sequence after the highest id already stored.
			auto res = this->RunQuery("SELECT setval(pg_get_serial_sequence('\"" + table + "\"', 'id'), GREATEST(COALESCE((SELECT MAX(`id`) FROM `" + table + "`), 0), 1)) AS `max`");
			if (res && res.Rows())
				this->sequence_max[table] = Warden::Convert<Serializable::Id>(res.Get(0, "max"), 0);
		}
	}

	if (known_cols.empty())
	{
		Warden::string query_text = "CREATE TABLE `" + table + "` (`id` BIGSERIAL PRIMARY KEY, `timestamp` TIMESTAMPTZ NULL DEFAULT CURRENT_TIMESTAMP";
		for (const auto &[column, _] : data.data)
		{
			known_cols.insert(column);
			query_text += ", `" + column + "` " + GetColumn(data.GetType(column));
		}
		query_text += ")";
		queries.push_back(query_text);
		queries.push_back("CREATE INDEX `" + table + "_timestamp_idx` ON `" + table + "` (`timestamp`)");
		this->sequence_max[table] = 0;
	}
	else
	{
		for (const auto &[column, _] : data.data)
		{
			if (known_cols.count(column) > 0)
				continue;

			known_cols.insert(column);
			queries.push_back("ALTER TABLE `" + table + "` ADD `" + column + "` " + GetColumn(data.GetType(column)));
		}
	}

	return queries;
}

Query PostgreSQLService::BuildInsert(const Warden::string &table, Serializable::Id id, Data &data)
{
	/* Empty columns not present in the data set */
	for (const auto &known_col : this->active_schema[table])
	{
		if (data.data.count(known_col) == 0)
			data.data[known_col];
	}

	Warden::string query_text = "INSERT INTO `" + table + "` (";
	if (id > 0)
		query_text += "`id`,";
	for (const auto &[field, _] : data.data)
		query_text += "`" + field + "`,";
	query_text.erase(query_text.end() - 1);
	query_text += ") VALUES (";
	if (id > 0)
		query_text += Warden::ToString(id) + ",";
	for (const auto &[field, _] : data.data)
		query_text += "@" + field + "@,";
	query_text.erase(query_text.end() - 1);
	query_text += ")";

	if (id > 0)
	{
		// Same as MySQL's ON DUPLICATE KEY UPDATE, which also refreshes the
		// timestamp column.
		query_text += " ON CONFLICT (`id`) DO UPDATE SET `timestamp` = CURRENT_TIMESTAMP";
		for (const auto &[field, _] : data.data)
			query_text += ", `" + field + "` = EXCLUDED.`" + field + "`";

		// A row written with an explicit id does not move the id sequence.
		auto &max = this->sequence_max[table];
		if (id > max)
		{
			max = id;
			query_text += "; SELECT setval(pg_get_serial_sequence('\"" + table + "\"', 'id'), GREATEST(" + Warden::ToString(id) + ", (SELECT MAX(`id`) FROM `" + table + "`)))";
		}
	}
	else
		query_text += " RETURNING `id` AS `warden_insert_id`";

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
			case Serialize::DataType::UINT:
			{
				// Numbers are passed as quoted literals so PostgreSQL converts
				// them, which keeps junk out of the query.
				if (buf.empty())
				{
					buf = "DEFAULT";
					escape = false;
				}
				break;
			}

			case Serialize::DataType::TEXT:
			{
				if (buf.empty())
				{
					buf = "DEFAULT";
					escape = false;
				}
				break;
			}
		}

		query.SetValue(field, buf, escape);
	}

	return query;
}

Query PostgreSQLService::GetTables(const Warden::string &prefix)
{
	Query query("SELECT `table_name` FROM `information_schema`.`tables` WHERE `table_schema` = current_schema() AND `table_name` LIKE @prefix@");
	query.SetValue("prefix", prefix + "%");
	return query;
}

void PostgreSQLService::Connect()
{
	if (this->sql)
		PQfinish(this->sql);

	this->sql = PQconnectdb(this->conninfo.c_str());
	if (!this->sql || PQstatus(this->sql) != CONNECTION_OK)
	{
		Warden::string error = this->sql ? PQerrorMessage(this->sql) : "out of memory";
		error.trim();
		throw SQL::Exception("Unable to connect to PostgreSQL service " + this->name + ": " + error);
	}

	// Keep NOTICE messages (e.g. "relation already exists, skipping") off stderr.
	PQsetNoticeProcessor(this->sql, [](void *, const char *) { }, nullptr);
	PQsetClientEncoding(this->sql, "UTF8");
	this->backend_pid = PQbackendPID(this->sql);

	Log(LOG_DEBUG) << "Successfully connected to PostgreSQL service " << this->name << " at " << this->display;
}

bool PostgreSQLService::CheckConnection()
{
	if (this->sql && PQstatus(this->sql) == CONNECTION_OK)
		return true;

	try
	{
		this->Connect();
	}
	catch (const SQL::Exception &)
	{
		return false;
	}
	return true;
}

Warden::string PostgreSQLService::Escape(const Warden::string &str)
{
	std::vector<char> buffer(str.length() * 2 + 1);
	int error = 0;
	PQescapeStringConn(this->sql, buffer.data(), str.c_str(), str.length(), &error);
	return buffer.data();
}

Warden::string PostgreSQLService::BuildQuery(const Query &q)
{
	// Turn `identifier` into "identifier", leaving string literals alone.
	Warden::string real_query;
	bool in_string = false;
	for (const auto chr : q.query)
	{
		if (chr == '\'')
			in_string = !in_string;
		real_query.push_back(!in_string && chr == '`' ? '"' : chr);
	}

	for (const auto &[name, value] : q.parameters)
		real_query = real_query.replace_all_cs("@" + name + "@", (value.escape ? ("'" + this->Escape(value.data) + "'") : value.data));

	return real_query;
}

Warden::string PostgreSQLService::FromUnixtime(time_t t)
{
	return "to_timestamp(" + Warden::ToString(t) + ")";
}

bool PostgreSQLService::ConnectListener()
{
	this->DropListener();

	this->listen_conn = PQconnectdb(this->conninfo.c_str());
	if (!this->listen_conn || PQstatus(this->listen_conn) != CONNECTION_OK)
	{
		Warden::string error = this->listen_conn ? PQerrorMessage(this->listen_conn) : "out of memory";
		error.trim();
		Log(LOG_NORMAL, "postgresql") << "PostgreSQL: Unable to open the listening connection for " << this->name << ": " << error;
		this->DropListener();
		return false;
	}
	PQsetNoticeProcessor(this->listen_conn, [](void *, const char *) { }, nullptr);

	std::set<Warden::string> channels;
	for (const auto &[_, channel] : this->listeners)
		channels.insert(channel);
	for (const auto &channel : channels)
	{
		char *quoted = PQescapeIdentifier(this->listen_conn, channel.c_str(), channel.length());
		PGresult *res = PQexec(this->listen_conn, (Warden::string("LISTEN ") + (quoted ? quoted : "")).c_str());
		const auto ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
		if (res)
			PQclear(res);
		if (quoted)
			PQfreemem(quoted);
		if (!ok)
		{
			Log(LOG_NORMAL, "postgresql") << "PostgreSQL: Unable to listen on " << channel << ": " << PQerrorMessage(this->listen_conn);
			this->DropListener();
			return false;
		}
	}

	PQsetnonblocking(this->listen_conn, 1);
	const int fd = dup(PQsocket(this->listen_conn));
	if (fd < 0)
	{
		this->DropListener();
		return false;
	}
	this->listen_socket = new NotifySocket(this, fd);
	Log(LOG_DEBUG) << "postgresql: listening for notifications on " << this->name;
	return true;
}

void PostgreSQLService::DropListener()
{
	delete this->listen_socket;
	this->listen_socket = nullptr;
	if (this->listen_conn)
		PQfinish(this->listen_conn);
	this->listen_conn = nullptr;
}

bool PostgreSQLService::Listen(const Warden::string &channel, SQL::Listener *listener)
{
	this->listeners[listener] = channel;
	if (this->listen_timer)
		return true; // Reconnecting; LISTEN is sent once it is back.
	if (this->ConnectListener())
		return true;
	this->listen_timer = new ListenReconnectTimer(this->owner, this);
	return true;
}

void PostgreSQLService::Unlisten(SQL::Listener *listener)
{
	this->listeners.erase(listener);
	if (this->listeners.empty())
	{
		this->DropListener();
		delete this->listen_timer;
		this->listen_timer = nullptr;
	}
}

bool PostgreSQLService::ReadNotifications()
{
	if (!this->listen_conn || !PQconsumeInput(this->listen_conn))
		return false;

	std::map<Warden::string, std::vector<Warden::string>> batches;
	const int own = this->backend_pid;
	while (PGnotify *notify = PQnotifies(this->listen_conn))
	{
		if (notify->be_pid != own)
			batches[notify->relname].push_back(notify->extra ? notify->extra : "");
		PQfreemem(notify);
	}

	for (const auto &[channel, payloads] : batches)
	{
		// A listener may unlisten while being called.
		std::vector<SQL::Listener *> targets;
		for (const auto &[listener, lchannel] : this->listeners)
			if (lchannel == channel)
				targets.push_back(listener);
		for (auto *listener : targets)
			if (this->listeners.count(listener))
				listener->OnNotifications(payloads);
	}
	return true;
}

void PostgreSQLService::ListenFailed()
{
	Log(LOG_NORMAL, "postgresql") << "PostgreSQL: Lost the listening connection for " << this->name << ", reconnecting";
	// The socket engine deletes the socket after this returns.
	this->listen_socket = nullptr;
	if (this->listen_conn)
		PQfinish(this->listen_conn);
	this->listen_conn = nullptr;
	if (!this->listen_timer)
		this->listen_timer = new ListenReconnectTimer(this->owner, this);
}

bool PostgreSQLService::RetryListener()
{
	if (this->listeners.empty() || !this->ConnectListener())
		return !this->listeners.empty();

	Log(LOG_NORMAL, "postgresql") << "PostgreSQL: Listening connection for " << this->name << " is back";
	this->listen_timer = nullptr; // Deleted by the timer manager when Tick returns false.
	std::vector<SQL::Listener *> targets;
	for (const auto &[listener, _] : this->listeners)
		targets.push_back(listener);
	for (auto *listener : targets)
		if (this->listeners.count(listener))
			listener->OnListenResync();
	return false;
}

bool NotifySocket::ProcessRead()
{
	if (this->service->ReadNotifications())
		return true;
	this->service->ListenFailed();
	return false;
}

void NotifySocket::ProcessError()
{
	this->service->ListenFailed();
}

bool ListenReconnectTimer::Tick()
{
	return this->service->RetryListener();
}

void DispatcherThread::Run()
{
	this->mutex.lock();

	while (!this->GetExitState())
	{
		if (!me->QueryRequests.empty())
		{
			QueryRequest &r = me->QueryRequests.front();
			this->mutex.unlock();

			Result sresult = r.service->RunQuery(r.query);

			this->mutex.lock();
			if (!me->QueryRequests.empty() && me->QueryRequests.front().query == r.query)
			{
				if (r.sqlinterface)
					me->FinishedRequests.push_back(QueryResult(r.sqlinterface, sresult));
				me->QueryRequests.pop_front();
			}
		}
		else
		{
			if (!me->FinishedRequests.empty())
				me->Notify();
			this->condvar.wait(this->mutex);
		}
	}

	this->mutex.unlock();
}

MODULE_INIT(ModulePostgreSQL)
