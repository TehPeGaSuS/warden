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

#include <stdexcept>

namespace SQL
{

	class Data final
		: public Serialize::Data
	{
	public:
		Warden::unordered_map<Warden::string> data;

		size_t Hash() const override
		{
			size_t hash = 0;
			for (const auto &[_, value] : this->data)
			{
				if (!value.empty())
					hash ^= Warden::hash_cs()(value);
			}
			return hash;
		}

		bool LoadInternal(const Warden::string &key, Warden::string &value) override
		{
			auto it = this->data.find(key);
			if (it == this->data.end())
				return false;

			value = it->second;
			return true;
		}

		bool StoreInternal(const Warden::string &key, const Warden::string &value) override
		{
			this->data[key] = value;
			return true;
		}
	};

	/** A SQL exception, can be thrown at various points
	 */
	class DllExport Exception : public ModuleException
	{
	public:
		Exception(const Warden::string &reason) : ModuleException(reason) { }

		virtual ~Exception() noexcept = default;
	};

	/** A SQL query
	 */

	struct QueryData final
	{
		Warden::string data;
		bool escape;
	};

	struct Query final
	{
		Warden::string query;
		std::map<Warden::string, QueryData> parameters;

		Query() { }
		Query(const Warden::string &q) : query(q) { }

		Query &operator=(const Warden::string &q)
		{
			this->query = q;
			this->parameters.clear();
			return *this;
		}

		bool operator==(const Query &other) const
		{
			return this->query == other.query;
		}

		inline bool operator!=(const Query &other) const
		{
			return !(*this == other);
		}

		template<typename T> void SetValue(const Warden::string &key, const T &value, bool escape = true)
		{
			auto str = Warden::TryString(value);
			if (!str.has_value())
				return;

			this->parameters[key].data = str.value();
			this->parameters[key].escape = escape;
		}
	};

	/** A result from a SQL query
	 */
	class Result
	{
	protected:
		/* Rows, column, item */
		std::vector<std::map<Warden::string, Warden::string> > entries;
		Query query;
		Warden::string error;
	public:
		unsigned int id = 0;
		Warden::string finished_query;

		Result() = default;
		Result(unsigned int i, const Query &q, const Warden::string &fq, const Warden::string &err = "") : query(q), error(err), id(i), finished_query(fq) { }

		inline operator bool() const { return this->error.empty(); }

		inline unsigned int GetID() const { return this->id; }
		inline const Query &GetQuery() const { return this->query; }
		inline const Warden::string &GetError() const { return this->error; }

		int Rows() const { return this->entries.size(); }

		const std::map<Warden::string, Warden::string> &Row(size_t index) const
		{
			try
			{
				return this->entries.at(index);
			}
			catch (const std::out_of_range &)
			{
				throw Exception("Out of bounds access to SQLResult");
			}
		}

		Warden::string Get(size_t index, const Warden::string &col) const
		{
			const std::map<Warden::string, Warden::string> rows = this->Row(index);

			std::map<Warden::string, Warden::string>::const_iterator it = rows.find(col);
			if (it == rows.end())
				throw Exception("Unknown column name in SQLResult: " + col);

			return it->second;
		}
	};

	/* An interface used by modules to retrieve the results
	 */
	class Interface
	{
	public:
		Module *owner;

		Interface(Module *m) : owner(m) { }
		virtual ~Interface() = default;

		virtual void OnResult(const Result &r) = 0;
		virtual void OnError(const Result &r) = 0;
	};

	/** Class providing the SQL service, modules call this to execute queries
	 */
	class Provider
		: public Service
	{
	public:
		Provider(Module *c, const Warden::string &n) : Service(c, "SQL::Provider", n) { }

		virtual void Run(Interface *i, const Query &query) = 0;

		virtual Result RunQuery(const Query &query) = 0;

		virtual std::vector<Query> CreateTable(const Warden::string &table, const Data &data) = 0;

		virtual Query BuildInsert(const Warden::string &table, Serializable::Id id, Data &data) = 0;

		virtual Query GetTables(const Warden::string &prefix) = 0;

		virtual Warden::string FromUnixtime(time_t) = 0;
	};

}
