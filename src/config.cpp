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

#include "services.h"
#include "config.h"
#include "mail.h"
#include "bots.h"
#include "access.h"
#include "opertype.h"
#include "channels.h"
#include "hashcomp.h"

#include <stack>
#include <stdexcept>

Configuration::File ServicesConf("warden.conf", false); // Configuration file name

Configuration::Conf *Config = NULL;

Configuration::Block Configuration::Block::EmptyBlock("");

Configuration::Block::Block(const Warden::string &n)
	: name(n)
	, position("<unknown>")
{
}

const Warden::string &Configuration::Block::GetName() const
{
	return name;
}

size_t Configuration::Block::CountBlock(const Warden::string &bname) const
{
	return blocks.count(bname);
}

Configuration::Block::BlockList Configuration::Block::GetBlocks(const Warden::string &bname) const
{
	return Warden::equal_range(blocks, bname);
}

const Configuration::Block &Configuration::Block::GetBlock(const Warden::string &bname, size_t num) const
{
	auto it = blocks.equal_range(bname);

	for (size_t i = 0; it.first != it.second; ++it.first, ++i)
	{
		if (i == num)
			return it.first->second;
	}
	return EmptyBlock;
}

Configuration::Block *Configuration::Block::GetMutableBlock(const Warden::string &bname, size_t num)
{
	auto it = blocks.equal_range(bname);

	for (size_t i = 0; it.first != it.second; ++it.first, ++i)
	{
		if (i == num)
			return &it.first->second;
	}
	return NULL;
}

bool Configuration::Block::Set(const Warden::string &tag, const Warden::string &value)
{
	items[tag] = value;
	return true;
}

const Configuration::Block::ItemMap &Configuration::Block::GetItems() const
{
	return items;
}

template<> const Warden::string Configuration::Block::Get(const Warden::string &tag, const Warden::string &def) const
{
	auto it = items.find(tag);
	if (it != items.end())
		return it->second;

	return def;
}

template<> time_t Configuration::Block::Get(const Warden::string &tag, const Warden::string &def) const
{
	return Warden::DoTime(Get<const Warden::string>(tag, def));
}

template<> bool Configuration::Block::Get(const Warden::string &tag, const Warden::string &def) const
{
	const Warden::string &str = Get<const Warden::string>(tag, def);
	return !str.empty() && !str.equals_ci("no") && !str.equals_ci("off") && !str.equals_ci("false") && !str.equals_ci("0");
}

static void ValidateNotEmpty(const Warden::string &block, const Warden::string &name, const Warden::string &value)
{
	if (value.empty())
		throw ConfigException("The value for <" + block + ":" + name + "> (" + value + ") cannot be empty!");
}

static void ValidateNoSpaces(const Warden::string &block, const Warden::string &name, const Warden::string &value)
{
	if (value.find(' ') != Warden::string::npos)
		throw ConfigException("The value for <" + block + ":" + name + "> (" + value + ") may not contain spaces!");
}

static void ValidateNotEmptyOrSpaces(const Warden::string &block, const Warden::string &name, const Warden::string &value)
{
	ValidateNotEmpty(block, name, value);
	ValidateNoSpaces(block, name, value);
}

template<typename T> static void ValidateNotZero(const Warden::string &block, const Warden::string &name, T value)
{
	if (!value)
		throw ConfigException("The value for <" + block + ":" + name + "> cannot be zero!");
}

Configuration::Conf::Conf() : Configuration::Block("")
{
	ReadTimeout = 0;
	DefPrivmsg = false;

	this->LoadConf(ServicesConf);

	for (const auto &[_,  include] : this->GetBlocks("include"))
	{
		const Warden::string &type = include.Get<const Warden::string>("type"),
					&file = include.Get<const Warden::string>("name");

		Configuration::File f(file, type == "executable");
		this->LoadConf(f);
	}

	FOREACH_MOD(OnReload, (*this));

	/* Check for modified values that aren't allowed to be modified */
	if (Config)
	{
		struct
		{
			Warden::string block;
			Warden::string name;
		} noreload[] = {
			{"serverinfo", "name"},
			{"serverinfo", "description"},
			{"serverinfo", "localhost"},
			{"serverinfo", "id"},
			{"serverinfo", "pid"},
			{"networkinfo", "nicklen"},
			{"networkinfo", "userlen"},
			{"networkinfo", "hostlen"},
			{"networkinfo", "chanlen"},
		};

		for (const auto &tag : noreload)
		{
			if (this->GetBlock(tag.block).Get<const Warden::string>(tag.name) != Config->GetBlock(tag.block).Get<const Warden::string>(tag.name))
				throw ConfigException("<" + tag.block + ":" + tag.name + "> can not be modified once set");
		}
	}

	const auto &serverinfo = this->GetBlock("serverinfo"), &options = this->GetBlock("options"),
		&mail = this->GetBlock("mail"), &networkinfo = this->GetBlock("networkinfo");

	const Warden::string &servername = serverinfo.Get<Warden::string>("name");

	ValidateNotEmptyOrSpaces("serverinfo", "name", servername);

	if (servername.find(' ') != Warden::string::npos || servername.find('.') == Warden::string::npos)
		throw ConfigException("serverinfo:name is not a valid server name");

	ValidateNotEmpty("serverinfo", "description", serverinfo.Get<const Warden::string>("description"));
	ValidateNotEmpty("serverinfo", "pid", serverinfo.Get<const Warden::string>("pid"));
	ValidateNotEmpty("serverinfo", "motd", serverinfo.Get<const Warden::string>("motd"));

	ValidateNotZero("options", "readtimeout", options.Get<time_t>("readtimeout"));

	ValidateNotZero("networkinfo", "nicklen", networkinfo.Get<unsigned>("nicklen", "1"));
	ValidateNotZero("networkinfo", "userlen", networkinfo.Get<unsigned>("userlen", "1"));
	ValidateNotZero("networkinfo", "hostlen", networkinfo.Get<unsigned>("hostlen", "1"));
	ValidateNotZero("networkinfo", "chanlen", networkinfo.Get<unsigned>("chanlen", "1"));

	spacesepstream(options.Get<const Warden::string>("ulineservers")).GetTokens(this->Ulines);

	if (mail.Get<bool>("usemail"))
		ValidateNotEmpty("mail", "sendfrom", mail.Get<const Warden::string>("sendfrom"));

	this->ReadTimeout = options.Get<time_t>("readtimeout");
	this->ServiceAlias = options.Get<bool>("servicealias");
	{
		std::vector<Warden::string> defaults;
		spacesepstream(this->GetModule("nickserv").Get<const Warden::string>("defaults")).GetTokens(defaults);
		this->DefPrivmsg = std::find(defaults.begin(), defaults.end(), "msg") != defaults.end();
	}
	this->DefLanguage = options.Get<const Warden::string>("defaultlanguage");
	this->TimeoutCheck = options.Get<time_t>("timeoutcheck");
	this->NickChars = networkinfo.Get<Warden::string>("nick_chars");

	for (const auto &[_,  uplink] : this->GetBlocks("uplink"))
	{
		int protocol;
		const Warden::string &protocolstr = uplink.Get<const Warden::string>("protocol", "ipv4");
		if (protocolstr == "ipv4")
			protocol = AF_INET;
		else if (protocolstr == "ipv6")
			protocol = AF_INET6;
		else if (protocolstr == "unix")
			protocol = AF_UNIX;
		else
			throw ConfigException("uplink:protocol must be set to ipv4, ipv6, or unix");

		const Warden::string &host = uplink.Get<const Warden::string>("host");
		ValidateNotEmptyOrSpaces("uplink", "host", host);

		int port = 0;
		if (protocol != AF_UNIX)
		{
			port = uplink.Get<int>("port");
			ValidateNotZero("uplink", "port", port);
		}

		const Warden::string &password = uplink.Get<const Warden::string>("password");
		ValidateNotEmptyOrSpaces("uplink", "password", password);
		if (password[0] == ':')
			throw ConfigException("uplink:password is not valid");

		this->Uplinks.emplace_back(host, port, password, protocol);
	}

	for (const auto &[_,  module] : this->GetBlocks("module"))
	{
		const Warden::string &modname = module.Get<const Warden::string>("name");

		ValidateNotEmptyOrSpaces("module", "name", modname);

		this->ModulesAutoLoad.push_back(modname);
	}

	for (const auto &[_,  opertype] : this->GetBlocks("opertype"))
	{
		const Warden::string &oname = opertype.Get<const Warden::string>("name"),
				&modes = opertype.Get<const Warden::string>("modes"),
				&inherits = opertype.Get<const Warden::string>("inherits"),
				&commands = opertype.Get<const Warden::string>("commands"),
				&privs = opertype.Get<const Warden::string>("privs");

		ValidateNotEmpty("opertype", "name", oname);

		auto *ot = new OperType(oname);
		ot->modes = modes;

		spacesepstream cmdstr(commands);
		for (Warden::string str; cmdstr.GetToken(str);)
			ot->AddCommand(str);

		spacesepstream privstr(privs);
		for (Warden::string str; privstr.GetToken(str);)
			ot->AddPriv(str);

		commasepstream inheritstr(inherits);
		for (Warden::string str; inheritstr.GetToken(str);)
		{
			/* Strip leading ' ' after , */
			if (str.length() > 1 && str[0] == ' ')
				str.erase(str.begin());
			for (auto *ot2 : this->MyOperTypes)
			{
				if (ot2->GetName().equals_ci(str))
				{
					Log() << "Inheriting commands and privs from " << ot2->GetName() << " to " << ot->GetName();
					ot->Inherits(ot2);
					break;
				}
			}
		}

		this->MyOperTypes.push_back(ot);
	}

	for (const auto &[_,  oper] : this->GetBlocks("oper"))
	{
		const Warden::string &nname = oper.Get<const Warden::string>("name"),
					&type = oper.Get<const Warden::string>("type"),
					&password = oper.Get<const Warden::string>("password"),
					&password_hash = oper.Get<const Warden::string>("password_hash"),
					&certfp = oper.Get<const Warden::string>("certfp"),
					&host = oper.Get<const Warden::string>("host"),
					&vhost = oper.Get<const Warden::string>("vhost");

		ValidateNotEmptyOrSpaces("oper", "name", nname);
		ValidateNotEmpty("oper", "type", type);

		OperType *ot = NULL;
		for (auto *opertype : this->MyOperTypes)
		{
			if (opertype->GetName() == type)
				ot = opertype;
		}
		if (ot == NULL)
			throw ConfigException("Oper block for " + nname + " has invalid oper type " + type);

		auto *o = new Oper(nname, ot);
		o->require_login = oper.Get<bool>("require_login");
		o->require_oper = oper.Get<bool>("require_oper");
		o->password = password;
		o->password_hash = password_hash;
		spacesepstream(certfp).GetTokens(o->certfp);
		spacesepstream(host).GetTokens(o->hosts);
		o->vhost = vhost;

		this->Opers.push_back(o);
	}

	for (const auto &[_, bi] : *BotListByNick)
		bi->conf = false;

	for (const auto &[_,  service] : this->GetBlocks("service"))
	{
		const Warden::string &nick = service.Get<const Warden::string>("nick"),
					&user = service.Get<const Warden::string>("user", nick.lower()),
					&host = service.Get<const Warden::string>("host", servername),
					&real = service.Get<const Warden::string>("real", nick),
					&modes = service.Get<const Warden::string>("modes"),
					&channels = service.Get<const Warden::string>("channels"),
					&alias = service.Get<const Warden::string>("alias", nick.upper());

		ValidateNotEmptyOrSpaces("service", "nick", nick);
		ValidateNotEmptyOrSpaces("service", "user", user);
		ValidateNotEmptyOrSpaces("service", "host", host);
		ValidateNotEmpty("service", "real", real);
		ValidateNoSpaces("service", "channels", channels);

		BotInfo *bi = BotInfo::Find(nick, true);
		if (!bi)
			bi = new BotInfo(nick, user, host, real, modes);

		bi->alias = alias;
		bi->conf = true;

		std::vector<Warden::string> oldchannels = bi->botchannels;
		bi->botchannels.clear();
		commasepstream sep(channels);
		for (Warden::string token; sep.GetToken(token);)
		{
			bi->botchannels.push_back(token);
			size_t ch = token.find('#');
			Warden::string chname, want_modes;
			if (ch == Warden::string::npos)
				chname = token;
			else
			{
				want_modes = token.substr(0, ch);
				chname = token.substr(ch);
			}
			bi->Join(chname);
			Channel *c = Channel::Find(chname);
			if (!c)
				continue; // Can't happen

			c->botchannel = true;

			/* Remove all existing modes */
			auto *memb = c->FindUser(bi);
			if (memb != NULL)
			{
				auto modes = memb->status.Modes();
				for (auto mode : modes)
					c->RemoveMode(bi, mode, bi->GetUID());
			}
			/* Set the new modes */
			for (char want_mode : want_modes)
			{
				ChannelMode *cm = ModeManager::FindChannelModeByChar(want_mode);
				if (cm == NULL)
					cm = ModeManager::FindChannelModeByChar(ModeManager::GetStatusChar(want_mode));
				if (cm && cm->type == MODE_STATUS)
					c->SetMode(bi, cm, bi->GetUID());
			}
		}
		for (const auto &oldchannel : oldchannels)
		{
			size_t ch = oldchannel.find('#');
			Warden::string chname = oldchannel.substr(ch != Warden::string::npos ? ch : 0);
			bool found = false;
			for (const auto &botchannel : bi->botchannels)
			{
				ch = botchannel.find('#');
				Warden::string ochname = botchannel.substr(ch != Warden::string::npos ? ch : 0);

				if (chname.equals_ci(ochname))
					found = true;
			}

			if (found)
				continue;

			Channel *c = Channel::Find(chname);
			if (c)
			{
				c->botchannel = false;
				bi->Part(c);
			}
		}
	}

	for (const auto &[_,  log] : this->GetBlocks("log"))
	{
		int logage = log.Get<int>("logage");
		bool rawio = log.Get<bool>("rawio");
		bool debug = log.Get<bool>("debug");

		LogInfo l(logage, rawio, debug);
		l.rotate = log.Get<bool>("rotate", "yes");

		l.bot = BotInfo::Find(log.Get<const Warden::string>("bot", "Global"), true);
		spacesepstream(log.Get<const Warden::string>("target")).GetTokens(l.targets);
		spacesepstream(log.Get<const Warden::string>("source")).GetTokens(l.sources);
		spacesepstream(log.Get<const Warden::string>("admin")).GetTokens(l.admin);
		spacesepstream(log.Get<const Warden::string>("override")).GetTokens(l.override);
		spacesepstream(log.Get<const Warden::string>("commands")).GetTokens(l.commands);
		spacesepstream(log.Get<const Warden::string>("servers")).GetTokens(l.servers);
		spacesepstream(log.Get<const Warden::string>("channels")).GetTokens(l.channels);
		spacesepstream(log.Get<const Warden::string>("users")).GetTokens(l.users);
		spacesepstream(log.Get<const Warden::string>("other")).GetTokens(l.normal);

		this->LogInfos.push_back(l);
	}

	for (const auto &[_, bi] : *BotListByNick)
		bi->commands.clear();
	for (const auto &[_,  command] : this->GetBlocks("command"))
	{
		const Warden::string &service = command.Get<const Warden::string>("service"),
					&nname = command.Get<const Warden::string>("name"),
					&cmd = command.Get<const Warden::string>("command"),
					&permission = command.Get<const Warden::string>("permission"),
					&group = command.Get<const Warden::string>("group");
		bool hide = command.Get<bool>("hide");

		ValidateNotEmptyOrSpaces("command", "service", service);
		ValidateNotEmpty("command", "name", nname);
		ValidateNotEmptyOrSpaces("command", "command", cmd);

		BotInfo *bi = this->GetClient(service);
		if (!bi)
			continue;

		CommandInfo &ci = bi->SetCommand(nname, cmd, permission);
		ci.group = group;
		ci.hide = hide;
	}

	PrivilegeManager::ClearPrivileges();
	for (const auto &[_,  privilege] : this->GetBlocks("privilege"))
	{
		const Warden::string &nname = privilege.Get<const Warden::string>("name"),
					&desc = privilege.Get<const Warden::string>("desc");
		int rank = privilege.Get<int>("rank");

		PrivilegeManager::AddPrivilege(Privilege(nname, desc, rank));
	}

	for (const auto &[_,  fantasy] : this->GetBlocks("fantasy"))
	{
		const Warden::string &nname = fantasy.Get<const Warden::string>("name"),
					&service = fantasy.Get<const Warden::string>("command"),
					&permission = fantasy.Get<const Warden::string>("permission"),
					&group = fantasy.Get<const Warden::string>("group");

		ValidateNotEmpty("fantasy", "name", nname);
		ValidateNotEmptyOrSpaces("fantasy", "command", service);

		CommandInfo &c = this->Fantasy[nname];
		c.name = service;
		c.permission = permission;
		c.group = group;
		c.hide = fantasy.Get<bool>("hide");
		c.prepend_channel = fantasy.Get<bool>("prepend_channel", "yes");
		c.require_privilege = fantasy.Get<bool>("require_privilege", "yes");
	}

	for (const auto &[_,  command_group] : this->GetBlocks("command_group"))
	{
		const Warden::string &nname = command_group.Get<const Warden::string>("name"),
					&description = command_group.Get<const Warden::string>("description");

		CommandGroup gr;
		gr.name = nname;
		gr.description = description;

		this->CommandGroups.push_back(gr);
	}

	/* Below here can't throw */

	if (Config)
		/* Clear existing conf opers */
		for (const auto &[_, nc] : *NickCoreList)
		{
			if (nc->o && std::find(Config->Opers.begin(), Config->Opers.end(), nc->o) != Config->Opers.end())
				nc->o = NULL;
		}
	/* Apply new opers */
	for (auto *o : this->Opers)
	{
		NickAlias *na = NickAlias::Find(o->name);
		if (!na)
			continue;

		if (!na->nc || na->nc->o)
		{
			// If the account is already an oper it might mean two oper blocks for the same nick, or
			// something else has configured them as an oper (like a module)
			continue;
		}

		na->nc->o = o;
		Log() << "Tied oper " << na->nc->display << " to type " << o->ot->GetName();
	}

	if (options.Get<const Warden::string>("casemap", "ascii") == "ascii")
		Warden::casemap = std::locale(std::locale(), new Warden::ascii_ctype<char>());
	else if (options.Get<const Warden::string>("casemap") == "rfc1459")
		Warden::casemap = std::locale(std::locale(), new Warden::rfc1459_ctype<char>());
	else
	{
		try
		{
			Warden::casemap = std::locale(options.Get<const Warden::string>("casemap").c_str());
		}
		catch (const std::runtime_error &)
		{
			Log() << "Unknown casemap " << options.Get<const Warden::string>("casemap") << " - casemap not changed";
		}
	}
	Warden::CaseMapRebuild();
}

Configuration::Conf::~Conf()
{
	for (const auto *opertype : MyOperTypes)
		delete opertype;

	for (const auto *oper : Opers)
		delete oper;
}

void Configuration::Conf::Post(Configuration::Conf *old)
{
	/* Apply module changes */
	for (const auto &mod : old->ModulesAutoLoad)
	{
		if (std::find(this->ModulesAutoLoad.begin(), this->ModulesAutoLoad.end(), mod) == this->ModulesAutoLoad.end())
			ModuleManager::UnloadModule(ModuleManager::FindModule(mod), NULL);
	}

	for (const auto &mod : this->ModulesAutoLoad)
	{
		if (std::find(old->ModulesAutoLoad.begin(), old->ModulesAutoLoad.end(), mod) == old->ModulesAutoLoad.end())
			ModuleManager::LoadModule(mod, NULL);
	}

	// A bad SMTP setup only warns on reload; each mail then fails with the
	// same message until it is fixed.
	const auto smtperr = Mail::CheckSMTPConfig(*this);
	if (!smtperr.empty())
		Log() << "Warning: " << smtperr << ". Mail will fail until this is fixed.";
	Mail::WarnSMTPConfig(*this);

	/* Apply opertype changes, as non-conf opers still point to the old oper types */
	for (unsigned i = Oper::opers.size(); i > 0; --i)
	{
		Oper *o = Oper::opers[i - 1];

		/* Oper's type is in the old config, so update it */
		if (std::find(old->MyOperTypes.begin(), old->MyOperTypes.end(), o->ot) != old->MyOperTypes.end())
		{
			OperType *ot = o->ot;
			o->ot = NULL;

			for (auto *opertype : MyOperTypes)
			{
				if (ot->GetName() == opertype->GetName())
					o->ot = opertype;
			}

			if (o->ot == NULL)
			{
				/* Oper block has lost type */
				auto it = std::find(old->Opers.begin(), old->Opers.end(), o);
				if (it != old->Opers.end())
					old->Opers.erase(it);

				it = std::find(this->Opers.begin(), this->Opers.end(), o);
				if (it != this->Opers.end())
					this->Opers.erase(it);

				delete o;
			}
		}
	}
}

Warden::string Configuration::Uplink::str() const
{
	switch (protocol)
	{
	case AF_INET:
		return Warden::Format("%s:%u", this->host.c_str(), this->port);
	case AF_INET6:
		return Warden::Format("[%s]:%u", this->host.c_str(), this->port);
	case AF_UNIX:
		return this->host;
	}

	// Should never be reached.
	return "";
}


Configuration::Block &Configuration::Conf::GetModule(const Module *m)
{
	if (!m)
		return Configuration::Block::EmptyBlock;

	return GetModule(m->name);
}

Configuration::Block &Configuration::Conf::GetModule(const Warden::string &mname)
{
	auto it = modules.find(mname);
	if (it != modules.end())
		return *it->second;

	auto *&block = modules[mname];

	/* Search for the block */
	for (auto iters = blocks.equal_range("module"); iters.first != iters.second; ++iters.first)
	{
		auto &b = iters.first->second;

		if (b.Get<const Warden::string>("name") == mname)
		{
			block = &b;
			break;
		}
	}

	if (!block)
		block = &Configuration::Block::EmptyBlock;

	return GetModule(mname);
}

BotInfo *Configuration::Conf::GetClient(const Warden::string &cname)
{
	auto it = bots.find(cname);
	if (it != bots.end())
		return BotInfo::Find(!it->second.empty() ? it->second : cname, true);

	auto &block = GetModule(cname.lower());
	const Warden::string &client = block.Get<const Warden::string>("client");
	bots[cname] = client;
	return GetClient(cname);
}

const Configuration::Block &Configuration::Conf::GetCommand(CommandSource &source)
{
	const Warden::string &block_name = source.c ? "fantasy" : "command";

	for (auto iters = blocks.equal_range(block_name); iters.first != iters.second; ++iters.first)
	{
		auto &b = iters.first->second;

		if (b.Get<Warden::string>("name") == source.command)
			return b;
	}

	return Configuration::Block::EmptyBlock;
}

Configuration::File::File(const Warden::string &n, bool e) : name(n), executable(e)
{
}

Configuration::File::~File()
{
	this->Close();
}

const Warden::string &Configuration::File::GetName() const
{
	return this->name;
}

Warden::string Configuration::File::GetPath() const
{
	return this->executable ? this->name : Warden::ExpandConfig(this->name);
}

bool Configuration::File::IsOpen() const
{
	return this->fp != NULL;
}

bool Configuration::File::Open()
{
	this->Close();
	this->fp = (this->executable ? popen(GetPath().c_str(), "r") : fopen(GetPath().c_str(), "r"));
	return this->fp != NULL;
}

void Configuration::File::Close()
{
	if (this->fp != NULL)
	{
		if (this->executable)
			pclose(this->fp);
		else
			fclose(this->fp);
		this->fp = NULL;
	}
}

bool Configuration::File::End() const
{
	return !this->IsOpen() || feof(this->fp);
}

Warden::string Configuration::File::Read()
{
	Warden::string ret;
	char buf[1024];
	while (fgets(buf, sizeof(buf), this->fp) != NULL)
	{
		char *nl = strchr(buf, '\n');
		if (nl != NULL)
			*nl = 0;
		else if (!this->End())
		{
			ret += buf;
			continue;
		}

		ret = buf;
		break;
	}

	return ret;
}

Configuration::FilePosition::FilePosition(const Warden::string& n)
	: name(n)
{
}

Warden::string Configuration::FilePosition::str() const
{
	return Warden::Format("%s:%zu:%zu", this->name.c_str(),
		this->line, this->column);
}

void Configuration::Conf::LoadConf(Configuration::File &file)
{
	if (file.GetName().empty())
		return;

	if (!file.Open())
	{
		throw ConfigException(Warden::Format("Configuration::File %s could not be opened: %s.",
			file.GetPath().c_str(), strerror(errno)));
	}

	Warden::string itemname, wordbuffer;
	std::stack<Configuration::Block *> block_stack;
	Configuration::FilePosition position(file.GetName());
	bool in_word = false, in_quote = false, in_comment = false;

	Log(LOG_DEBUG) << "Start to read conf " << file.GetPath();
	// Start reading characters...
	while (!file.End())
	{
		Warden::string line = file.Read();

		position.column = 0;
		position.line++;

		/* If this line is completely empty and we are in a quote, just append a newline */
		if (line.empty() && in_quote)
			wordbuffer += "\n";

		for (unsigned c = 0, len = line.length(); c < len; ++c)
		{
			position.column++;
			char ch = line[c];
			if (in_quote)
			{
				/* Strip leading white spaces from multi line quotes */
				if (c == 0)
				{
					while (c < len && isspace(line[c]))
						++c;
					ch = line[c];
				}

				/* Allow \" in quotes */
				if (ch == '\\' && c + 1 < len && line[c + 1] == '"')
					wordbuffer += line[++c];
				else if (ch == '"')
					in_quote = in_word = false;
				else if (ch)
					wordbuffer += ch;
			}
			else if (in_comment)
			{
				if (ch == '*' && c + 1 < len && line[c + 1] == '/')
				{
					in_comment = false;
					++c;
					// We might be at an eol, so continue on and process it
				}
				else
					continue;
			}
			else if (ch == '#' || (ch == '/' && c + 1 < len && line[c + 1] == '/'))
				c = len - 1; // Line comment, ignore the rest of the line (much like this one!)
			else if (ch == '/' && c + 1 < len && line[c + 1] == '*')
			{
				// Multiline (or less than one line) comment
				in_comment = true;
				++c;
				continue;
			}
			else if (!in_word && (ch == '(' || ch == '_' || ch == ')'))
				;
			else if (ch == '"')
			{
				// Quotes are valid only in the value position
				if (block_stack.empty() || itemname.empty())
				{
					file.Close();
					throw ConfigException("Unexpected quoted string: " + position.str());
				}
				if (in_word || !wordbuffer.empty())
				{
					file.Close();
					throw ConfigException("Unexpected quoted string (prior unhandled words): " + position.str());
				}
				in_quote = in_word = true;
			}
			else if (ch == '=')
			{
				if (block_stack.empty())
				{
					file.Close();
					throw ConfigException("Config item outside of section (or stray '='): " + position.str());
				}

				if (!itemname.empty() || wordbuffer.empty())
				{
					file.Close();
					throw ConfigException("Stray '=' sign or item without value: " + position.str());
				}

				in_word = false;
				itemname = wordbuffer;
				wordbuffer.clear();
			}
			else if (ch == '{')
			{
				if (wordbuffer.empty())
				{
					block_stack.push(NULL);
					// Commented or unnamed section
					continue;
				}

				if (!block_stack.empty() && !block_stack.top())
				{
					// Named block inside of a commented block
					in_word = false;
					wordbuffer.clear();
					block_stack.push(NULL);
					continue;
				}

				auto *b = block_stack.empty() ? this : block_stack.top();
				auto it = b->blocks.emplace(wordbuffer, Configuration::Block(wordbuffer));
				b = &it->second;
				b->position = position;
				block_stack.push(b);

				in_word = false;
				wordbuffer.clear();
				continue;
			}
			else if (ch == ' ' || ch == '\r' || ch == '\t')
			{
				// Terminate word
				in_word = false;
			}
			else if (ch == ';' || ch == '}')
				;
			else
			{
				if (!in_word && !wordbuffer.empty())
				{
					file.Close();
					throw ConfigException("Unexpected word: " + position.str());
				}
				wordbuffer += ch;
				in_word = true;
			}

			if (ch == ';' || ch == '}' || c + 1 >= len)
			{
				bool eol = c + 1 >= len;

				if (!eol && in_quote)
					// Allow ; and } in quoted strings
					continue;

				if (in_quote)
				{
					// Quotes can span multiple lines; all we need to do is go to the next line without clearing things
					wordbuffer += "\n";
					continue;
				}

				in_word = false;
				if (!itemname.empty())
				{
					if (block_stack.empty())
					{
						file.Close();
						throw ConfigException("Stray ';' outside of block: " + position.str());
					}

					auto *b = block_stack.top();
					if (b)
					{
						Log(LOG_DEBUG) << "ln " << position.line << " EOL: s='" << b->name << "' '" << itemname << "' set to '" << wordbuffer << "'";
						b->items[itemname] = ReplaceVars(wordbuffer, file, position);
					}

					wordbuffer.clear();
					itemname.clear();
				}

				if (ch == '}')
				{
					if (block_stack.empty())
					{
						file.Close();
						throw ConfigException("Stray '}': " + position.str());
					}

					block_stack.pop();
				}
			}
		}
	}

	file.Close();

	if (in_comment)
		throw ConfigException("Unterminated multiline comment at end of file: " + file.GetName());
	if (in_quote)
		throw ConfigException("Unterminated quote at end of file: " + file.GetName());
	if (!itemname.empty() || !wordbuffer.empty())
		throw ConfigException("Unexpected garbage at end of file: " + file.GetName());
	if (!block_stack.empty())
	{
		if (block_stack.top())
			throw ConfigException("Unterminated block at end of file. Block was opened at " + block_stack.top()->position.str());
		else
			throw ConfigException("Unterminated commented block at end of file: " + file.GetName());
	}
}

Warden::string Configuration::Conf::ReplaceVars(const Warden::string &str, const Configuration::File &file, const Configuration::FilePosition &position)
{
	Warden::string ret;
	for (auto it = str.begin(); it != str.end(); )
	{
		if (*it != '$')
		{
			ret.push_back(*it++);
			continue;
		}

		if (++it == str.end() || *it != '{')
		{
			ret.push_back('$');
			continue;
		}

		it++;
		Warden::string var;
		while (it != str.end() && *it != '}')
			var.push_back(*it++);

		if (it == str.end())
			throw ConfigException("Unterminated variable: " + position.str());

		it++;
		if (var.compare(0, 4, "env.", 4) == 0)
		{
			// This is an environment variable rather than a defined variable
			const char* envstr = getenv(var.c_str() + 4);
			if (envstr && envstr)
				ret.append(envstr);
			continue;
		}

		auto found = false;
		for (const auto &[_,  define] : this->GetBlocks("define"))
		{
			const auto defname = define.Get<const Warden::string>("name");
			if (defname == var)
			{
				ret.append(define.Get<const Warden::string>("value"));
				found = true;
				break;
			}
		}

		if (!found)
			throw ConfigException("Undefined variable: " + var + " at " + position.str());
	}

	if (!str.equals_cs(ret))
		Log(LOG_DEBUG) << "Expanded \"" << str << "\" to \"" << ret << "\"";
	return ret;
}
