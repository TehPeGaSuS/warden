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

#include "account.h"
#include "regchannel.h"
#include "users.h"
#include "opertype.h"
#include "miscutils.h"

namespace Configuration
{
	/** Represents a position within a config file. */
	class CoreExport FilePosition final
	{
	public:
		Warden::string name;
		size_t line = 0;
		size_t column = 0;
		FilePosition(const Warden::string& n);
		Warden::string str() const;
	};

	class CoreExport Block
	{
		friend class Configuration::Conf;

	public:
		typedef Warden::map<Warden::string> ItemMap;
		typedef Warden::multimap<Block> BlockMap;
		typedef Warden::iterator_range<BlockMap::const_iterator> BlockList;

	private:
		Warden::string name;
		ItemMap items;
		BlockMap blocks;
		FilePosition position;

		/* Represents a missing tag. */
		static Block EmptyBlock;

	public:
		Block(const Warden::string &);
		const Warden::string &GetName() const;
		size_t CountBlock(const Warden::string &name) const;
		BlockList GetBlocks(const Warden::string &name) const;
		const Block &GetBlock(const Warden::string &name, size_t num = 0) const;
		Block *GetMutableBlock(const Warden::string &name, size_t num = 0);

		template<typename T> T Get(const Warden::string &tag, const Warden::string &def = "") const
		{
			return Warden::TryConvert<T>(this->Get<const Warden::string>(tag, def)).value_or(T());
		}

		bool Set(const Warden::string &tag, const Warden::string &value);
		const ItemMap &GetItems() const;
	};

	template<> CoreExport const Warden::string Block::Get(const Warden::string &tag, const Warden::string &def) const;
	template<> CoreExport time_t Block::Get(const Warden::string &tag, const Warden::string &def) const;
	template<> CoreExport bool Block::Get(const Warden::string &tag, const Warden::string &def) const;

	/** Represents a configuration file
	 */
	class File final
	{
		Warden::string name;
		bool executable;
		FILE *fp = nullptr;
	public:
		File(const Warden::string &, bool);
		~File();
		const Warden::string &GetName() const;
		Warden::string GetPath() const;

		bool IsOpen() const;
		bool Open();
		void Close();
		bool End() const;
		Warden::string Read();
	};

	struct Uplink;

	class CoreExport Conf final
		: public Block
	{
	private:
		/** Replaces defined variables within a string. */
		Warden::string ReplaceVars(const Warden::string &str, const File &file, const FilePosition &position);

	public:
		/* options:readtimeout */
		time_t ReadTimeout;
		/* If we should default to privmsging clients */
		bool DefPrivmsg;
		/* Default language */
		Warden::string DefLanguage;
		/* options:timeoutcheck */
		time_t TimeoutCheck;
		/* options:servicealias */
		bool ServiceAlias;
		/* networkinfo:nickchars */
		Warden::string NickChars;

		/* List of uplink servers to try and connect to */
		std::vector<Uplink> Uplinks;
		/* A vector of our logfile options */
		std::vector<LogInfo> LogInfos;
		/* Array of ulined servers */
		std::vector<Warden::string> Ulines;
		/* List of available opertypes */
		std::vector<OperType *> MyOperTypes;
		/* List of pairs of opers and their opertype from the config */
		std::vector<Oper *> Opers;
		/* Map of fantasy commands */
		CommandInfo::map Fantasy;
		/* Command groups */
		std::vector<CommandGroup> CommandGroups;
		/* List of modules to autoload */
		std::vector<Warden::string> ModulesAutoLoad;

		/* module configuration blocks */
		std::map<Warden::string, Block *> modules;
		Warden::map<Warden::string> bots;

		Conf();
		~Conf();

		void LoadConf(File &file);
		void Post(Conf *old);

		Block &GetModule(const Module *);
		Block &GetModule(const Warden::string &name);

		BotInfo *GetClient(const Warden::string &name);

		const Block &GetCommand(CommandSource &);
	};

	struct Uplink final
	{
		Warden::string host;
		unsigned port;
		Warden::string password;
		int protocol;

		Uplink(const Warden::string &_host, int _port, const Warden::string &_password, int _protocol) : host(_host), port(_port), password(_password), protocol(_protocol) { }
		inline bool operator==(const Uplink &other) const { return host == other.host && port == other.port && password == other.password && protocol == other.protocol; }
		inline bool operator!=(const Uplink &other) const { return !(*this == other); }
		Warden::string str() const;
	};
}

/** This class can be used on its own to represent an exception, or derived to represent a module-specific exception.
 * When a module whishes to abort, e.g. within a constructor, it should throw an exception using ModuleException or
 * a class derived from ModuleException. If a module throws an exception during its constructor, the module will not
 * be loaded. If this happens, the error message returned by ModuleException::GetReason will be displayed to the user
 * attempting to load the module, or dumped to the console if the ircd is currently loading for the first time.
 */
class CoreExport ConfigException final
	: public CoreException
{
public:
	/** Default constructor, just uses the error message 'Config threw an exception'.
	 */
	ConfigException() : CoreException("Config threw an exception", "Config Parser") { }
	/** This constructor can be used to specify an error message before throwing.
	 */
	ConfigException(const Warden::string &message) : CoreException(message, "Config Parser") { }
	/** This destructor solves world hunger, cancels the world debt, and causes the world to end.
	 * Actually no, it does nothing. Never mind.
	 * @throws Nothing!
	 */
	virtual ~ConfigException() noexcept = default;
};

extern Configuration::File ServicesConf;
extern CoreExport Configuration::Conf *Config;
