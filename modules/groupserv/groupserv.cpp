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

// GroupServ: account groups named like !staff, with per-member flags, in the
// style of Atheme's GroupServ. Ideas and command set from Atheme and from
// reverse's third-party Anope GroupServ.
//
// Members are stored by account (not by name), so a dropped account's access
// goes with it and can't be inherited by whoever registers the name next.

#include "module.h"
#include "modules/memoserv/service.h"

#define GROUP_TYPE "GSGroup"

namespace
{
	// F founder, f change flags, A view the access list, m memos, c channel
	// access, v vhost, s SET, i invite, b banned from joining.
	const Warden::string ALL_FLAGS = "FfAmcvsib";
	const Warden::string MEMBER_FLAGS = "fAmcvsi"; // What * gives.

	struct Member final
	{
		NickCore *nc;
		Warden::string flags;
		time_t added;
	};
}

struct Group final
	: Serializable
{
	Warden::string name;
	Warden::string description, url, email, channel, joinflags, vhost;
	bool open = false, pub = false, acsnolimit = false, regnolimit = false, neverop = false;
	time_t registered = 0;
	std::vector<Member> members;
	std::set<NickCore *> invited;

	Group() : Serializable(GROUP_TYPE) { }
	~Group() override;

	Member *Find(const NickCore *nc)
	{
		for (auto &m : members)
			if (m.nc == nc)
				return &m;
		return nullptr;
	}

	bool Has(const NickCore *nc, char flag)
	{
		auto *m = nc ? Find(nc) : nullptr;
		return m && m->flags.find(flag) != Warden::string::npos;
	}

	unsigned Count(char flag) const
	{
		unsigned n = 0;
		for (const auto &m : members)
			if (m.flags.find(flag) != Warden::string::npos)
				++n;
		return n;
	}

	Warden::string Founders() const
	{
		Warden::string out;
		for (const auto &m : members)
			if (m.flags.find('F') != Warden::string::npos)
				out += (out.empty() ? "" : ", ") + m.nc->display;
		return out;
	}
};

static Warden::map<Group *> Groups;

Group::~Group()
{
	Groups.erase(this->name);
}

struct GroupType final
	: Serialize::Type
{
	GroupType() : Serialize::Type(GROUP_TYPE) { }

	void Serialize(Serializable *obj, Serialize::Data &data) const override
	{
		const auto *g = static_cast<const Group *>(obj);
		data.Store("name", g->name);
		data.Store("description", g->description);
		data.Store("url", g->url);
		data.Store("email", g->email);
		data.Store("channel", g->channel);
		data.Store("joinflags", g->joinflags);
		data.Store("vhost", g->vhost);
		data.Store("open", g->open);
		data.Store("public", g->pub);
		data.Store("acsnolimit", g->acsnolimit);
		data.Store("regnolimit", g->regnolimit);
		data.Store("neverop", g->neverop);
		data.Store("registered", g->registered);

		// account-id:+flags:added, space separated.
		std::stringstream members;
		for (const auto &m : g->members)
			members << m.nc->GetId() << ":+" << m.flags << ":" << m.added << " ";
		data.Store("members", members.str());

		std::stringstream invited;
		for (auto *nc : g->invited)
			invited << nc->GetId() << " ";
		data.Store("invited", invited.str());
	}

	Serializable *Unserialize(Serializable *obj, Serialize::Data &data) const override
	{
		auto *g = obj ? warden_dynamic_static_cast<Group *>(obj) : new Group();
		if (!obj)
		{
			g->name = data.Load("name");
			if (g->name.empty() || Groups.count(g->name))
			{
				delete g;
				return nullptr;
			}
			Groups[g->name] = g;
		}

		g->description = data.Load("description");
		g->url = data.Load("url");
		g->email = data.Load("email");
		g->channel = data.Load("channel");
		g->joinflags = data.Load("joinflags");
		g->vhost = data.Load("vhost");
		g->open = data.Load<bool>("open");
		g->pub = data.Load<bool>("public");
		g->acsnolimit = data.Load<bool>("acsnolimit");
		g->regnolimit = data.Load<bool>("regnolimit");
		g->neverop = data.Load<bool>("neverop");
		g->registered = data.Load<time_t>("registered");

		g->members.clear();
		spacesepstream members(data.Load("members"));
		for (Warden::string entry; members.GetToken(entry); )
		{
			sepstream fields(entry, ':');
			Warden::string id, flags, added;
			fields.GetToken(id);
			fields.GetToken(flags);
			fields.GetToken(added);
			auto *nc = NickCore::FindId(Warden::Convert<uint64_t>(id, 0));
			if (nc && !g->Find(nc))
				g->members.push_back({ nc, flags.length() > 1 ? flags.substr(1) : "", Warden::Convert<time_t>(added, 0) });
		}

		g->invited.clear();
		spacesepstream invited(data.Load("invited"));
		for (Warden::string id; invited.GetToken(id); )
			if (auto *nc = NickCore::FindId(Warden::Convert<uint64_t>(id, 0)))
				g->invited.insert(nc);

		return g;
	}
};

// Applies changes like "+Af-v", "*" or "-*" to flags. Returns false if a
// character isn't a known flag.
static bool ApplyFlags(Warden::string &flags, const Warden::string &changes)
{
	auto add = true;
	for (auto c : changes)
	{
		if (c == '+')
			add = true;
		else if (c == '-')
			add = false;
		else if (c == '*')
		{
			for (auto f : (add ? MEMBER_FLAGS : ALL_FLAGS))
			{
				const auto pos = flags.find(f);
				if (add && pos == Warden::string::npos)
					flags.push_back(f);
				else if (!add && pos != Warden::string::npos)
					flags.erase(pos, 1);
			}
		}
		else if (ALL_FLAGS.find(c) != Warden::string::npos)
		{
			const auto pos = flags.find(c);
			if (add && pos == Warden::string::npos)
				flags.push_back(c);
			else if (!add && pos != Warden::string::npos)
				flags.erase(pos, 1);
		}
		else
			return false;
	}

	// Keep them in a fixed order so they read the same everywhere.
	Warden::string sorted;
	for (auto f : ALL_FLAGS)
		if (flags.find(f) != Warden::string::npos)
			sorted.push_back(f);
	flags = sorted;
	return true;
}

static bool IsValidName(const Warden::string &name)
{
	if (name.length() < 2 || name.length() > 32 || name[0] != '!')
		return false;
	for (size_t i = 1; i < name.length(); ++i)
		if (!isalnum(static_cast<unsigned char>(name[i])) && name[i] != '-' && name[i] != '_' && name[i] != '.')
			return false;
	return true;
}

static bool IsAdmin(CommandSource &source)
{
	return source.HasPriv("groupserv/admin");
}

static bool CanSee(CommandSource &source)
{
	return source.HasPriv("groupserv/auspex") || IsAdmin(source);
}

// Finds a group, or replies that it doesn't exist.
static Group *FindGroup(CommandSource &source, const Warden::string &name)
{
	auto it = Groups.find(name);
	if (it == Groups.end())
	{
		source.Reply(_("The group \002%s\002 does not exist."), name.c_str());
		return nullptr;
	}
	return it->second;
}

// Channels that only let a group's members in (ChanServ SET GROUPONLY).
static const char *GROUPONLY_EXT = "GROUPONLY";

// Group vhosts are marked with this as their creator, so they can be taken
// back when the member leaves or loses +v.
static Warden::string VHostTag(const Warden::string &group)
{
	return "GroupServ (" + group + ")";
}

static void RevokeVHost(const Group *g, NickCore *nc)
{
	const auto tag = VHostTag(g->name);
	for (auto *na : *nc->aliases)
	{
		if (na->HasVHost() && na->GetVHostCreator() == tag)
		{
			FOREACH_MOD(OnDeleteVHost, (na));
			na->RemoveVHost();
		}
	}
}

// Removes a dropped group from every channel access list, like Atheme.
static void Drop(Group *g)
{
	for (const auto &m : g->members)
		RevokeVHost(g, m.nc);

	for (const auto &[_, ci] : *RegisteredChannelList)
	{
		for (unsigned i = ci->GetAccessCount(); i > 0; --i)
		{
			if (ci->GetAccess(i - 1)->Mask().equals_ci(g->name))
				delete ci->EraseAccess(i - 1);
		}

		auto *only = ci->GetExt<Warden::string>(GROUPONLY_EXT);
		if (only && only->equals_ci(g->name))
			ci->Shrink<Warden::string>(GROUPONLY_EXT);
	}
	delete g;
}

class CommandGSRegister final
	: public Command
{
public:
	CommandGSRegister(Module *creator) : Command(creator, "groupserv/register", 1, 1)
	{
		this->SetDesc(_("Register a group"));
		this->SetSyntax(_("\037!group\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		const auto &name = params[0];
		auto *nc = source.GetAccount();
		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}
		if (nc->HasExt("UNCONFIRMED"))
		{
			source.Reply(_("You must confirm your account before you can register a group."));
			return;
		}
		if (!IsValidName(name))
		{
			source.Reply(_("\002%s\002 is not a valid group name. It must start with \002!\002 and be up to 32 letters, digits, '-', '_' or '.'."), name.c_str());
			return;
		}
		if (Groups.count(name))
		{
			source.Reply(_("The group \002%s\002 already exists."), name.c_str());
			return;
		}

		const auto maxgroups = Config->GetModule(this->owner).Get<unsigned>("maxgroups", "5");
		unsigned owned = 0;
		for (const auto &[_, g] : Groups)
			if (!g->regnolimit && g->Has(nc, 'F'))
				++owned;
		if (maxgroups && owned >= maxgroups && !IsAdmin(source))
		{
			source.Reply(_("You have too many groups registered (the limit is %u)."), maxgroups);
			return;
		}

		auto *g = new Group();
		g->name = name;
		g->registered = Warden::CurTime;
		g->members.push_back({ nc, "F" + MEMBER_FLAGS, Warden::CurTime });
		ApplyFlags(g->members.back().flags, "");
		Groups[name] = g;

		Log(LOG_COMMAND, source, this) << "to register group " << name;
		source.Reply(_("The group \002%s\002 has been registered to \002%s\002."), name.c_str(), nc->display.c_str());
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
				"Registers a group, with you as its founder. Group names start "
				"with \002!\002, e.g. \002!staff\002. You can own up to %u groups."
			),
			Config->GetModule(this->owner).Get<unsigned>("maxgroups", "5"));
		return true;
	}
};

class CommandGSDrop final
	: public Command
{
	// A code tied to this group's registration, so DROP needs two steps.
	static Warden::string Key(const Group *g)
	{
		const auto h = std::hash<std::string>()((g->name.lower() + Warden::ToString(g->registered)).str());
		return Warden::ToString(h % 1000000);
	}

public:
	CommandGSDrop(Module *creator) : Command(creator, "groupserv/drop", 1, 2)
	{
		this->SetDesc(_("Drop a group"));
		this->SetSyntax(_("\037!group\037 [\037key\037]"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		auto *g = FindGroup(source, params[0]);
		if (!g)
			return;
		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}
		if (!g->Has(source.GetAccount(), 'F'))
		{
			source.Reply(ACCESS_DENIED);
			return;
		}

		if (params.size() < 2)
		{
			source.Reply(_("This will drop the group \002%s\002 and all its members' access. To confirm, type \002%s\002."), g->name.c_str(),
				source.service->GetQueryCommand("groupserv/drop", g->name + " " + Key(g)).c_str());
			return;
		}
		if (params[1] != Key(g))
		{
			source.Reply(_("Invalid key for dropping \002%s\002."), g->name.c_str());
			return;
		}

		const auto name = g->name;
		Log(LOG_COMMAND, source, this) << "to drop group " << name;
		Drop(g);
		source.Reply(_("The group \002%s\002 has been dropped."), name.c_str());
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Drops a group you founded. You are first given a key to confirm it with."));
		return true;
	}
};

class CommandGSFDrop final
	: public Command
{
public:
	CommandGSFDrop(Module *creator) : Command(creator, "groupserv/fdrop", 1, 1)
	{
		this->SetDesc(_("Drop any group"));
		this->SetSyntax(_("\037!group\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		auto *g = FindGroup(source, params[0]);
		if (!g)
			return;
		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		const auto name = g->name;
		Log(LOG_ADMIN, source, this) << "to drop group " << name << " (founders: " << g->Founders() << ")";
		Drop(g);
		source.Reply(_("The group \002%s\002 has been dropped."), name.c_str());
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Drops any group, without a key. For services operators."));
		return true;
	}
};

class CommandGSFlags
	: public Command
{
protected:
	void Change(CommandSource &source, Group *g, const Warden::string &target, const Warden::string &changes, bool force)
	{
		auto *na = NickAlias::Find(target);
		if (!na)
		{
			source.Reply(NICK_X_NOT_REGISTERED, target.c_str());
			return;
		}
		NickCore *nc = na->nc;
		auto *src = source.GetAccount();

		auto *m = g->Find(nc);
		const auto oldflags = m ? m->flags : "";
		auto flags = oldflags;
		if (!ApplyFlags(flags, changes))
		{
			source.Reply(_("\002%s\002 contains an unknown flag. See \002%s\002 for the flags."), changes.c_str(),
				source.service->GetQueryCommand("generic/help", "FLAGS").c_str());
			return;
		}

		const auto had = [&](char f) { return oldflags.find(f) != Warden::string::npos; };
		const auto has = [&](char f) { return flags.find(f) != Warden::string::npos; };

		// Members may always take their own access away.
		const auto self = nc == src && flags.empty();
		if (!force && !self)
		{
			if (has('F') && !had('F') && !g->Has(src, 'F'))
			{
				source.Reply(_("Only a founder can make someone a founder."));
				return;
			}
			if (had('F') && !has('F') && !g->Has(src, 'F'))
			{
				source.Reply(_("Only a founder can remove a founder."));
				return;
			}
		}
		if (has('F'))
			ApplyFlags(flags, "+f");

		if (had('F') && !has('F') && g->Count('F') == 1)
		{
			source.Reply(_("You may not remove the last founder of \002%s\002."), g->name.c_str());
			return;
		}
		if (has('c') && !had('c') && nc->HasExt("NEVEROP"))
		{
			source.Reply(_("\002%s\002 does not wish to be added to channel access lists (NEVEROP is on)."), nc->display.c_str());
			return;
		}

		if (flags == oldflags && !(m && flags.empty()))
		{
			source.Reply(_("Group \002%s\002 access for \002%s\002 is unchanged."), g->name.c_str(), nc->display.c_str());
			return;
		}

		if (had('v') && !has('v'))
			RevokeVHost(g, nc);

		if (flags.empty())
		{
			g->members.erase(std::remove_if(g->members.begin(), g->members.end(), [nc](const auto &mem) { return mem.nc == nc; }), g->members.end());
			Log(force ? LOG_ADMIN : LOG_COMMAND, source, this) << "to remove " << nc->display << " from " << g->name;
			source.Reply(_("\002%s\002 has been removed from \002%s\002."), nc->display.c_str(), g->name.c_str());
			return;
		}

		if (!m)
		{
			const auto max = Config->GetModule(this->owner).Get<unsigned>("maxgroupacs", "100");
			if (!force && max && !g->acsnolimit && g->members.size() >= max)
			{
				source.Reply(_("The access list of \002%s\002 is full."), g->name.c_str());
				return;
			}
			g->members.push_back({ nc, flags, Warden::CurTime });
			g->invited.erase(nc);
		}
		else
			m->flags = flags;

		Log(force ? LOG_ADMIN : LOG_COMMAND, source, this) << "to set the flags of " << nc->display << " on " << g->name << " to +" << flags;
		source.Reply(_("\002%s\002 now has flags \002+%s\002 on \002%s\002."), nc->display.c_str(), flags.c_str(), g->name.c_str());
	}

	void ShowList(CommandSource &source, Group *g)
	{
		ListFormatter list(source.GetAccount());
		list.AddColumn(_("Number")).AddColumn(_("Account")).AddColumn(_("Flags")).AddColumn(_("Added"));
		list.SetFlexible(_("{number}: \002{account}\002 +{flags} (added {added})"));
		unsigned i = 0;
		for (const auto &m : g->members)
		{
			ListFormatter::ListEntry entry;
			entry["Number"] = Warden::ToString(++i);
			entry["Account"] = m.nc->display;
			entry["Flags"] = m.flags.empty() ? "" : "+" + m.flags;
			entry["Added"] = Warden::strftime(m.added, source.GetAccount(), true);
			list.AddEntry(entry);
		}
		source.Reply(_("Access list of \002%s\002:"), g->name.c_str());
		list.SendTo(source);
		source.Reply(_("End of \002%s\002 access list."), g->name.c_str());
	}

public:
	CommandGSFlags(Module *creator, const Warden::string &cname = "groupserv/flags") : Command(creator, cname, 1, 3)
	{
		this->SetDesc(_("View or change who is in a group and what they can do"));
		this->SetSyntax(_("\037!group\037 [\037account\037 [\037changes\037]]"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		auto *g = FindGroup(source, params[0]);
		if (!g)
			return;

		auto *src = source.GetAccount();
		if (params.size() < 2)
		{
			if (!g->Has(src, 'A') && !g->Has(src, 'f') && !CanSee(source))
				source.Reply(ACCESS_DENIED);
			else
				ShowList(source, g);
			return;
		}

		if (params.size() < 3)
		{
			this->OnSyntaxError(source, "");
			return;
		}
		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		// Changing others needs +f; anyone can remove themselves.
		auto *na = NickAlias::Find(params[1]);
		const auto self = na && na->nc == src && (params[2] == "-*" || params[2] == "-");
		if (!self && !g->Has(src, 'f'))
		{
			source.Reply(ACCESS_DENIED);
			return;
		}
		Change(source, g, params[1], params[2], false);
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Without an account, lists the group's members and their flags "
			"(needs +A). With one, changes that account's flags (needs +f); a "
			"member who loses all flags leaves the group, and you can always "
			"leave a group yourself with \002-*\002."
			"\n\n"
			"The flags are:\n"
			"  F - founder: everything, including SET OPEN/GROUPNAME and DROP\n"
			"  f - change members' flags\n"
			"  A - view the member list\n"
			"  m - read memos sent to the group\n"
			"  c - get the group's channel access\n"
			"  v - take vhosts offered to the group\n"
			"  s - use SET on the group\n"
			"  i - invite accounts to the group\n"
			"  b - banned: can't JOIN the group\n"
			"\n"
			"\002*\002 means all of them except F and b. Only a founder can add or "
			"remove F, and the last founder can't be removed."
		));
		return true;
	}
};

class CommandGSFFlags final
	: public CommandGSFlags
{
public:
	CommandGSFFlags(Module *creator) : CommandGSFlags(creator, "groupserv/fflags")
	{
		this->SetDesc(_("Change anyone's flags in any group"));
		this->ClearSyntax();
		this->SetSyntax(_("\037!group\037 \037account\037 \037changes\037"));
		this->min_params = 3;
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		auto *g = FindGroup(source, params[0]);
		if (!g)
			return;
		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}
		Change(source, g, params[1], params[2], true);
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Like \002FLAGS\002, for services operators: changes anyone's flags in any group, without the usual checks."));
		return true;
	}
};

class CommandGSJoin final
	: public Command
{
public:
	CommandGSJoin(Module *creator) : Command(creator, "groupserv/join", 1, 1)
	{
		this->SetDesc(_("Join an open group, or one you were invited to"));
		this->SetSyntax(_("\037!group\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		auto *g = FindGroup(source, params[0]);
		if (!g)
			return;
		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		auto *nc = source.GetAccount();
		const auto invited = g->invited.count(nc) > 0;
		if (g->Has(nc, 'b'))
		{
			source.Reply(ACCESS_DENIED);
			return;
		}
		if (g->Find(nc))
		{
			source.Reply(_("You are already a member of \002%s\002."), g->name.c_str());
			return;
		}
		if (!g->open && !invited)
		{
			source.Reply(_("The group \002%s\002 is not open to anyone joining."), g->name.c_str());
			return;
		}

		const auto max = Config->GetModule(this->owner).Get<unsigned>("maxgroupacs", "100");
		if (!invited && max && !g->acsnolimit && g->members.size() >= max)
		{
			source.Reply(_("The access list of \002%s\002 is full."), g->name.c_str());
			return;
		}

		Warden::string flags;
		ApplyFlags(flags, g->joinflags.empty() ? Config->GetModule(this->owner).Get<const Warden::string>("joinflags") : g->joinflags);
		// Never hand out founder or ban by joining.
		ApplyFlags(flags, "-Fb");
		g->members.push_back({ nc, flags, Warden::CurTime });
		g->invited.erase(nc);

		Log(LOG_COMMAND, source, this) << "to join " << g->name;
		source.Reply(_("You are now a member of \002%s\002."), g->name.c_str());
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Joins a group that is open (\002SET OPEN\002) or that you were invited to with \002INVITE\002. You get the group's join flags."));
		return true;
	}
};

class CommandGSInvite final
	: public Command
{
public:
	CommandGSInvite(Module *creator) : Command(creator, "groupserv/invite", 2, 2)
	{
		this->SetDesc(_("Invite an account to a group"));
		this->SetSyntax(_("\037!group\037 \037account\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		auto *g = FindGroup(source, params[0]);
		if (!g)
			return;
		if (!g->Has(source.GetAccount(), 'i'))
		{
			source.Reply(ACCESS_DENIED);
			return;
		}
		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		auto *na = NickAlias::Find(params[1]);
		if (!na)
		{
			source.Reply(NICK_X_NOT_REGISTERED, params[1].c_str());
			return;
		}
		NickCore *nc = na->nc;
		if (g->Find(nc))
		{
			source.Reply(_("\002%s\002 is already a member of \002%s\002."), nc->display.c_str(), g->name.c_str());
			return;
		}
		if (g->invited.count(nc))
		{
			source.Reply(_("\002%s\002 has already been invited to \002%s\002."), nc->display.c_str(), g->name.c_str());
			return;
		}

		const auto maxinvites = Config->GetModule(this->owner).Get<unsigned>("maxinvites", "50");
		if (maxinvites && g->invited.size() >= maxinvites)
		{
			source.Reply(_("\002%s\002 has too many open invitations; wait until some are used."), g->name.c_str());
			return;
		}

		g->invited.insert(nc);
		Log(LOG_COMMAND, source, this) << "to invite " << nc->display << " to " << g->name;
		source.Reply(_("\002%s\002 has been invited to \002%s\002."), nc->display.c_str(), g->name.c_str());

		const auto joincmd = source.service->GetQueryCommand("groupserv/join", g->name);
		bool told = false;
		for (auto *u : nc->users)
		{
			u->SendMessage(source.service, _("%s invited you to the group \002%s\002. To join it, type \002%s\002."), source.GetNick().c_str(), g->name.c_str(), joincmd.c_str());
			told = true;
		}

		if (!told && MemoServ::service)
		{
			const auto text = Warden::Format(Language::Translate(nc, _("%s invited you to the group %s. To join it, type %s.")), source.GetNick().c_str(), g->name.c_str(), joincmd.c_str());
			MemoServ::service->Send(source.service->nick, nc->display, text, true);
		}
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Invites an account to the group (needs +i). They are told, or sent a memo if they are offline, and can then \002JOIN\002 even if the group isn't open."));
		return true;
	}
};

class CommandGSInfo final
	: public Command
{
public:
	CommandGSInfo(Module *creator) : Command(creator, "groupserv/info", 1, 1)
	{
		this->SetDesc(_("Show information about a group"));
		this->SetSyntax(_("\037!group\037"));
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		auto *g = FindGroup(source, params[0]);
		if (!g)
			return;

		auto *nc = source.GetAccount();
		const auto member = nc && g->Find(nc) && !g->Has(nc, 'b');

		InfoFormatter info(nc);
		info[_("Registered")] = Warden::strftime(g->registered, nc);
		if (g->pub || member || CanSee(source))
		{
			info[_("Founder")] = g->Founders();
			info[_("Members")] = Warden::ToString(g->members.size());
		}
		if (!g->description.empty())
			info[_("Description")] = g->description;
		if (!g->channel.empty())
			info[_("Channel")] = g->channel;
		if (!g->url.empty())
			info[_("URL")] = g->url;
		if (!g->email.empty())
			info[_("Email")] = g->email;
		if (!g->joinflags.empty() && (member || CanSee(source)))
			info[_("Join flags")] = "+" + g->joinflags;
		if (!g->vhost.empty() && (member || CanSee(source)))
			info[_("Vhost")] = g->vhost;

		if (g->open)
			info.AddOption(_("Open"));
		if (g->pub)
			info.AddOption(_("Public"));
		if (g->acsnolimit)
			info.AddOption(_("No access list limit"));
		if (g->regnolimit)
			info.AddOption(_("Not counted towards the founders' group limit"));

		source.Reply(_("Information about group \002%s\002:"), g->name.c_str());
		info.SendTo(source);
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Shows information about a group. Its founders and member count are only shown to members, unless the group is public (\002SET PUBLIC\002)."));
		return true;
	}
};

class CommandGSList final
	: public Command
{
public:
	CommandGSList(Module *creator) : Command(creator, "groupserv/list", 0, 1)
	{
		this->SetDesc(_("List groups"));
		this->SetSyntax(_("[\037pattern\037]"));
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		const auto pattern = params.empty() ? "*" : params[0];
		const auto all = CanSee(source);
		const auto listmax = Config->GetModule(this->owner).Get<unsigned>("listmax", "50");

		ListFormatter list(source.GetAccount());
		list.AddColumn(_("Group")).AddColumn(_("Founder")).AddColumn(_("Description"));
		list.SetFlexible(_("\002{group}\002 ({founder}) {description}"));
		unsigned matches = 0;
		for (const auto &[name, g] : Groups)
		{
			if (!all && !g->pub)
				continue;
			if (!Warden::Match(name, pattern))
				continue;
			if (++matches > listmax)
				continue;

			ListFormatter::ListEntry entry;
			entry["Group"] = name;
			entry["Founder"] = g->Founders();
			entry["Description"] = g->description;
			list.AddEntry(entry);
		}

		if (!matches)
		{
			source.Reply(_("No groups match \002%s\002."), pattern.c_str());
			return;
		}
		source.Reply(_("Groups matching \002%s\002:"), pattern.c_str());
		list.SendTo(source);
		source.Reply(_("End of list - %u/%u shown."), std::min(matches, listmax), matches);
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Lists the public groups matching a pattern (all groups for services operators)."));
		return true;
	}
};

class CommandGSListChans final
	: public Command
{
public:
	CommandGSListChans(Module *creator) : Command(creator, "groupserv/listchans", 1, 1)
	{
		this->SetDesc(_("List the channels a group has access to"));
		this->SetSyntax(_("\037!group\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		auto *g = FindGroup(source, params[0]);
		if (!g)
			return;
		if (!g->Has(source.GetAccount(), 'c') && !CanSee(source))
		{
			source.Reply(ACCESS_DENIED);
			return;
		}

		unsigned count = 0;
		for (const auto &[_, ci] : *RegisteredChannelList)
		{
			for (unsigned i = 0; i < ci->GetAccessCount(); ++i)
			{
				const auto *access = ci->GetAccess(i);
				if (access->Mask().equals_ci(g->name))
				{
					source.Reply(_("\002%s\002 in \002%s\002"), access->AccessSerialize().c_str(), ci->name.c_str());
					++count;
				}
			}
		}

		if (!count)
			source.Reply(_("The group \002%s\002 is on no channel access list."), g->name.c_str());
		else
			source.Reply(_("End of list - \002%s\002 is on %u channel access list(s)."), g->name.c_str(), count);
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Lists the channel access lists the group is on, and with what access (needs +c)."));
		return true;
	}
};

class CommandGSSet final
	: public Command
{
	bool Toggle(CommandSource &source, Group *g, bool &value, const Warden::string &setting, const char *what)
	{
		if (setting.equals_ci("ON"))
			value = true;
		else if (setting.equals_ci("OFF"))
			value = false;
		else
		{
			this->OnSyntaxError(source, "");
			return false;
		}
		Log(LOG_COMMAND, source, this) << "to set " << what << " " << (value ? "on" : "off") << " on " << g->name;
		if (value)
			source.Reply(_("\002%s\002 of \002%s\002 is now \002on\002."), what, g->name.c_str());
		else
			source.Reply(_("\002%s\002 of \002%s\002 is now \002off\002."), what, g->name.c_str());
		return true;
	}

public:
	CommandGSSet(Module *creator) : Command(creator, "groupserv/set", 2, 3)
	{
		this->SetDesc(_("Change a group's settings"));
		this->SetSyntax(_("\037!group\037 \037option\037 [\037value\037]"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		auto *g = FindGroup(source, params[0]);
		if (!g)
			return;
		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		auto *nc = source.GetAccount();
		const auto option = params[1].upper();
		const auto value = params.size() > 2 ? params[2] : "";
		const auto founder = g->Has(nc, 'F');
		const auto setter = g->Has(nc, 's') || founder;

		if (option == "DESCRIPTION" || option == "URL" || option == "EMAIL" || option == "CHANNEL")
		{
			if (!setter)
			{
				source.Reply(ACCESS_DENIED);
				return;
			}
			if (option == "CHANNEL" && !value.empty() && value[0] != '#')
			{
				source.Reply(_("\002%s\002 is not a channel."), value.c_str());
				return;
			}
			if (option == "EMAIL" && !value.empty() && !Mail::Validate(value))
			{
				source.Reply(MAIL_X_INVALID, value.c_str());
				return;
			}

			auto &field = option == "DESCRIPTION" ? g->description : option == "URL" ? g->url : option == "EMAIL" ? g->email : g->channel;
			field = value;
			Log(LOG_COMMAND, source, this) << "to set " << option << " of " << g->name << " to " << (value.empty() ? "nothing" : value);
			if (value.empty())
				source.Reply(_("\002%s\002 of \002%s\002 has been cleared."), option.c_str(), g->name.c_str());
			else
				source.Reply(_("\002%s\002 of \002%s\002 is now \002%s\002."), option.c_str(), g->name.c_str(), value.c_str());
		}
		else if (option == "JOINFLAGS")
		{
			if (!setter)
			{
				source.Reply(ACCESS_DENIED);
				return;
			}
			Warden::string flags;
			if (!value.empty() && !value.equals_ci("OFF") && !value.equals_ci("NONE"))
			{
				if (value.find('-') != Warden::string::npos || !ApplyFlags(flags, value) || flags.find_first_of("Fb") != Warden::string::npos)
				{
					source.Reply(_("Join flags must be flags to add, without \002F\002 or \002b\002, e.g. \002+Ac\002."));
					return;
				}
			}
			g->joinflags = flags;
			Log(LOG_COMMAND, source, this) << "to set the join flags of " << g->name << " to " << (flags.empty() ? "none" : "+" + flags);
			if (flags.empty())
				source.Reply(_("The join flags of \002%s\002 have been cleared."), g->name.c_str());
			else
				source.Reply(_("The join flags of \002%s\002 are now \002+%s\002."), g->name.c_str(), flags.c_str());
		}
		else if (option == "NEVEROP")
		{
			if (!setter)
				source.Reply(ACCESS_DENIED);
			else
				Toggle(source, g, g->neverop, value, "NEVEROP");
		}
		else if (option == "PUBLIC")
		{
			if (!setter)
				source.Reply(ACCESS_DENIED);
			else
				Toggle(source, g, g->pub, value, "PUBLIC");
		}
		else if (option == "OPEN")
		{
			if (!founder)
				source.Reply(ACCESS_DENIED);
			else if (value.equals_ci("ON") && !Config->GetModule(this->owner).Get<bool>("enable_open_groups"))
				source.Reply(_("Open groups have been disabled by the network."));
			else
				Toggle(source, g, g->open, value, "OPEN");
		}
		else if (option == "ACSNOLIMIT" || option == "REGNOLIMIT")
		{
			if (!IsAdmin(source))
				source.Reply(ACCESS_DENIED);
			else
				Toggle(source, g, option == "ACSNOLIMIT" ? g->acsnolimit : g->regnolimit, value, option == "ACSNOLIMIT" ? "ACSNOLIMIT" : "REGNOLIMIT");
		}
		else if (option == "VHOST")
		{
			if (!IsAdmin(source))
			{
				source.Reply(ACCESS_DENIED);
				return;
			}
			if (value.empty() || value.equals_ci("OFF"))
			{
				g->vhost.clear();
				Log(LOG_ADMIN, source, this) << "to clear the vhost of " << g->name;
				source.Reply(_("The vhost of \002%s\002 has been cleared."), g->name.c_str());
				return;
			}
			const auto sample = Warden::Template(value, { { "account", "account" }, { "nick", "nick" } });
			if (!IRCD->IsHostValid(sample))
			{
				source.Reply(_("\002%s\002 is not a valid vhost."), value.c_str());
				return;
			}
			g->vhost = value;
			Log(LOG_ADMIN, source, this) << "to set the vhost of " << g->name << " to " << value;
			source.Reply(_("Members of \002%s\002 with +v can now take the vhost \002%s\002 with \002%s\002."), g->name.c_str(), value.c_str(),
				source.service->GetQueryCommand("groupserv/vhost", g->name).c_str());
		}
		else if (option == "GROUPNAME")
		{
			if (!founder)
			{
				source.Reply(ACCESS_DENIED);
				return;
			}
			if (!IsValidName(value))
			{
				source.Reply(_("\002%s\002 is not a valid group name. It must start with \002!\002 and be up to 32 letters, digits, '-', '_' or '.'."), value.c_str());
				return;
			}
			if (Groups.count(value) && !value.equals_ci(g->name))
			{
				source.Reply(_("The group \002%s\002 already exists."), value.c_str());
				return;
			}

			// Channel access entries for the group follow the new name.
			const auto oldname = g->name;
			unsigned moved = 0;
			for (const auto &[_, ci] : *RegisteredChannelList)
			{
				for (unsigned i = 0; i < ci->GetAccessCount(); ++i)
				{
					auto *access = ci->GetAccess(i);
					if (access->Mask().equals_ci(oldname))
					{
						access->SetMask(value, ci);
						++moved;
					}
				}

				auto *only = ci->GetExt<Warden::string>(GROUPONLY_EXT);
				if (only && only->equals_ci(oldname))
					ci->Extend<Warden::string>(GROUPONLY_EXT, value);
			}

			// Vhosts taken from the group keep following it.
			const auto oldtag = VHostTag(oldname), newtag = VHostTag(value);
			for (const auto &[_, na] : *NickAliasList)
				if (na->HasVHost() && na->GetVHostCreator() == oldtag)
					na->SetVHost(na->GetVHostIdent(), na->GetVHostHost(), newtag, na->GetVHostCreated());

			Groups.erase(oldname);
			g->name = value;
			Groups[value] = g;
			Log(LOG_COMMAND, source, this) << "to rename " << oldname << " to " << value << " (" << moved << " channel access entries updated)";
			source.Reply(_("The group \002%s\002 has been renamed to \002%s\002."), oldname.c_str(), value.c_str());
		}
		else
			this->OnSyntaxError(source, "");
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Changes a group's settings. These need +s:\n"
			"  DESCRIPTION, URL, EMAIL, CHANNEL [\037value\037] - set or clear them\n"
			"  JOINFLAGS [\037flags\037|OFF] - flags given to people who JOIN\n"
			"  PUBLIC {ON|OFF} - show founders and members to everyone\n"
			"  NEVEROP {ON|OFF} - keep the group off channel access lists\n"
			"These need +F:\n"
			"  OPEN {ON|OFF} - let anyone JOIN without an invitation\n"
			"  GROUPNAME \037!newname\037 - rename the group\n"
			"These are for services operators:\n"
			"  ACSNOLIMIT {ON|OFF} - no limit on the access list size\n"
			"  REGNOLIMIT {ON|OFF} - don't count it towards its founders' limit\n"
			"  VHOST [\037vhost\037|OFF] - a vhost members with +v can take; it may use {account} and {nick}"
		));
		return true;
	}
};

class CommandGSVHost final
	: public Command
{
public:
	CommandGSVHost(Module *creator) : Command(creator, "groupserv/vhost", 1, 1)
	{
		this->SetDesc(_("Take a group's vhost"));
		this->SetSyntax(_("\037!group\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		auto *g = FindGroup(source, params[0]);
		if (!g)
			return;
		auto *nc = source.GetAccount();
		if (!g->Has(nc, 'v') || g->Has(nc, 'b'))
		{
			source.Reply(ACCESS_DENIED);
			return;
		}
		if (g->vhost.empty())
		{
			source.Reply(_("The group \002%s\002 has no vhost."), g->name.c_str());
			return;
		}
		if (!IRCD->CanSetVHost)
		{
			source.Reply(_("Vhosts are not available on this network."));
			return;
		}
		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		// The nick in use if it is one of the account's, otherwise its display nick.
		auto *na = source.GetUser() ? NickAlias::Find(source.GetNick()) : nullptr;
		if (!na || na->nc != nc)
			na = nc->na;
		const auto host = Warden::Template(g->vhost, { { "account", nc->display }, { "nick", na->nick } });
		if (!IRCD->IsHostValid(host))
		{
			source.Reply(_("\002%s\002 is not a valid vhost."), host.c_str());
			return;
		}

		na->SetVHost("", host, VHostTag(g->name));
		FOREACH_MOD(OnSetVHost, (na));
		Log(LOG_COMMAND, source, this) << "to take the vhost " << host << " from " << g->name;
		source.Reply(_("Your vhost is now \002%s\002, from \002%s\002. You lose it if you leave the group or lose +v."), host.c_str(), g->name.c_str());
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Sets your vhost to the group's vhost (needs +v). The vhost is set by services operators with \002SET VHOST\002. You lose it again if you leave the group, lose +v, or the group is dropped."));
		return true;
	}
};

class CommandCSSetGroupOnly final
	: public Command
{
public:
	CommandCSSetGroupOnly(Module *creator, const Warden::string &cname = "chanserv/set/grouponly")
		: Command(creator, cname, 2, 2)
	{
		this->SetDesc(_("Only let a group's members join the channel"));
		this->SetSyntax(_("\037channel\037 {\037!group\037 | OFF}"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		auto *ci = ChannelInfo::Find(params[0]);
		if (!ci)
		{
			source.Reply(CHAN_X_NOT_REGISTERED, params[0].c_str());
			return;
		}

		EventReturn MOD_RESULT;
		FOREACH_RESULT(OnSetChannelOption, MOD_RESULT, (source, this, ci, params[1]));
		if (MOD_RESULT == EVENT_STOP)
			return;
		if (MOD_RESULT != EVENT_ALLOW && !source.AccessFor(ci).HasPriv("SET") && source.permission.empty() && !source.HasPriv("chanserv/administration"))
		{
			source.Reply(ACCESS_DENIED);
			return;
		}

		const auto override = !source.AccessFor(ci).HasPriv("SET");
		if (params[1].equals_ci("OFF"))
		{
			ci->Shrink<Warden::string>(GROUPONLY_EXT);
			Log(override ? LOG_OVERRIDE : LOG_COMMAND, source, this, ci) << "to turn GROUPONLY off";
			source.Reply(_("Anyone may join \002%s\002 again."), ci->name.c_str());
			return;
		}

		auto it = Groups.find(params[1]);
		if (it == Groups.end())
		{
			source.Reply(_("The group \002%s\002 does not exist."), params[1].c_str());
			return;
		}

		ci->Extend<Warden::string>(GROUPONLY_EXT, it->second->name);
		Log(override ? LOG_OVERRIDE : LOG_COMMAND, source, this, ci) << "to only let members of " << it->second->name << " join";
		source.Reply(_("Only members of \002%s\002 (and users with access to the channel) may join \002%s\002 now."), it->second->name.c_str(), ci->name.c_str());
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Only lets members of a group join the channel. Anyone else who "
			"joins is banned and kicked, except users with access to the channel "
			"and services operators. Banned members (+b) count as non-members. "
			"\002OFF\002 lets anyone join again."
		));
		return true;
	}
};

class GroupServCore final
	: public Module
{
	GroupType grouptype;
	CommandGSRegister commandgsregister;
	CommandGSDrop commandgsdrop;
	CommandGSFDrop commandgsfdrop;
	CommandGSFlags commandgsflags;
	CommandGSFFlags commandgsfflags;
	CommandGSJoin commandgsjoin;
	CommandGSInvite commandgsinvite;
	CommandGSInfo commandgsinfo;
	CommandGSList commandgslist;
	CommandGSListChans commandgslistchans;
	CommandGSSet commandgsset;
	CommandGSVHost commandgsvhost;
	CommandCSSetGroupOnly commandcssetgrouponly;
	SerializableExtensibleItem<Warden::string> grouponly;
	Reference<BotInfo> GroupServ;

public:
	GroupServCore(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, PSEUDOCLIENT | VENDOR)
		, commandgsregister(this), commandgsdrop(this), commandgsfdrop(this)
		, commandgsflags(this), commandgsfflags(this), commandgsjoin(this)
		, commandgsinvite(this), commandgsinfo(this), commandgslist(this)
		, commandgslistchans(this), commandgsset(this)
		, commandgsvhost(this), commandcssetgrouponly(this), grouponly(this, GROUPONLY_EXT)
	{
	}

	~GroupServCore() override
	{
		for (auto it = Groups.begin(); it != Groups.end(); )
			delete (it++)->second;
	}

	void OnReload(Configuration::Conf &conf) override
	{
		const auto &gsnick = conf.GetModule(this).Get<const Warden::string>("client");
		if (gsnick.empty())
			throw ConfigException(Module::name + ": <client> must be defined");

		auto *bi = BotInfo::Find(gsnick, true);
		if (!bi)
			throw ConfigException(Module::name + ": no bot named " + gsnick);
		GroupServ = bi;
	}

	EventReturn OnPreHelp(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		if (!params.empty() || source.c || source.service != *GroupServ)
			return EVENT_CONTINUE;
		source.Reply(_(
				"\002%s\002 manages groups of accounts named like \002!staff\002. "
				"Members get flags that say what they can do in the group."
			),
			GroupServ->nick.c_str());
		source.Reply(" ");
		return EVENT_CONTINUE;
	}

	void OnDelCore(NickCore *nc) override
	{
		for (auto it = Groups.begin(); it != Groups.end(); )
		{
			auto *g = (it++)->second;
			g->invited.erase(nc);

			auto *m = g->Find(nc);
			if (!m)
				continue;
			const auto wasfounder = m->flags.find('F') != Warden::string::npos;
			g->members.erase(std::remove_if(g->members.begin(), g->members.end(), [nc](const auto &mem) { return mem.nc == nc; }), g->members.end());
			if (!wasfounder || g->Count('F'))
				continue;

			// The last founder is gone: the longest-standing member who could
			// change flags takes over, or else the longest-standing member.
			Member *heir = nullptr;
			for (auto &mem : g->members)
				if (mem.flags.find('b') == Warden::string::npos && (!heir || (mem.flags.find('f') != Warden::string::npos && heir->flags.find('f') == Warden::string::npos)))
					heir = &mem;

			if (heir)
			{
				ApplyFlags(heir->flags, "+F" + MEMBER_FLAGS);
				Log(LOG_NORMAL, "groupserv/founder", GroupServ) << "Founder of " << g->name << " (" << nc->display << ") was dropped; " << heir->nc->display << " is the new founder";
			}
			else
			{
				Log(LOG_NORMAL, "groupserv/drop", GroupServ) << "Dropping group " << g->name << ": its last founder " << nc->display << " was dropped and no member is left";
				Drop(g);
			}
		}
	}

	// MemoServ SEND !group: a copy to every member with +m, as in Atheme.
	EventReturn OnPreCommand(CommandSource &source, Command *command, std::vector<Warden::string> &params) override
	{
		if (command->name != "memoserv/send" || params.size() < 2 || params[0].empty() || params[0][0] != '!')
			return EVENT_CONTINUE;

		auto *g = FindGroup(source, params[0]);
		auto *nc = source.GetAccount();
		auto *u = source.GetUser();
		if (!g)
			return EVENT_STOP;
		if (!nc || !u)
		{
			source.Reply(NICK_IDENTIFY_REQUIRED);
			return EVENT_STOP;
		}
		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return EVENT_STOP;
		}
		if (nc->HasExt("UNCONFIRMED"))
		{
			source.Reply(_("You must confirm your account before you may send a memo."));
			return EVENT_STOP;
		}

		// The send delay applies once to the whole group.
		const auto delay = Config->GetModule("memoserv").Get<time_t>("senddelay");
		if (delay > 0 && !u->HasPriv("memoserv/no-limit") && u->lastmemosend + delay > Warden::CurTime)
		{
			source.Reply(_("Please wait %s before using the %s command again."), Warden::Duration(u->lastmemosend + delay - Warden::CurTime, nc).c_str(), source.command.nobreak().c_str());
			return EVENT_STOP;
		}
		if (!MemoServ::service)
			return EVENT_CONTINUE;

		const auto text = "[" + g->name + "] " + params[1];
		const auto last = u->lastmemosend;
		unsigned sent = 0, failed = 0;
		for (const auto &m : g->members)
		{
			if (m.nc == nc || m.flags.find('m') == Warden::string::npos || m.flags.find('b') != Warden::string::npos)
				continue;

			// Each memo goes through the normal checks (full box, ignore list).
			u->lastmemosend = last;
			if (MemoServ::service->Send(source.GetNick(), m.nc->display, text) == MemoServ::MEMO_SUCCESS)
				++sent;
			else
				++failed;
		}
		u->lastmemosend = Warden::CurTime;

		Log(LOG_COMMAND, source, command) << "to send a memo to " << sent << " member(s) of " << g->name;
		if (!sent && !failed)
			source.Reply(_("Nobody else in \002%s\002 receives the group's memos."), g->name.c_str());
		else if (failed)
			source.Reply(_("Memo sent to \002%u\002 member(s) of \002%s\002 (%u could not receive it)."), sent, g->name.c_str(), failed);
		else
			source.Reply(_("Memo sent to \002%u\002 member(s) of \002%s\002."), sent, g->name.c_str());
		return EVENT_STOP;
	}

	EventReturn OnChanAccessMatches(const ChanAccess *access, const User *u, const NickCore *acc) override
	{
		if (!acc && u)
			acc = u->Account();
		auto it = Groups.find(access->Mask());
		if (!acc || it == Groups.end())
			return EVENT_CONTINUE;

		// +c gives the group's channel access; +b never does.
		auto *g = it->second;
		return g->Has(acc, 'c') && !g->Has(acc, 'b') ? EVENT_ALLOW : EVENT_CONTINUE;
	}

	EventReturn OnCheckAccessMask(CommandSource &source, ChannelInfo *ci, Warden::string &mask) override
	{
		auto it = Groups.find(mask);
		if (it == Groups.end())
		{
			source.Reply(_("The group \002%s\002 does not exist."), mask.c_str());
			return EVENT_STOP;
		}
		if (it->second->neverop)
		{
			source.Reply(_("The group \002%s\002 does not wish to be added to channel access lists (NEVEROP is on)."), it->second->name.c_str());
			return EVENT_STOP;
		}
		mask = it->second->name;
		return EVENT_ALLOW;
	}

	void OnJoinChannel(User *u, Channel *c) override
	{
		if (!c->ci || u->server == Me || u->server->IsULined())
			return;
		auto *only = grouponly.Get(c->ci);
		if (!only)
			return;

		auto it = Groups.find(*only);
		auto *nc = u->Account();
		if (it != Groups.end() && nc && it->second->Find(nc) && !it->second->Has(nc, 'b'))
			return;
		if (!c->ci->AccessFor(u).empty() || u->IsServicesOper())
			return;

		const auto mask = c->ci->GetIdealBan(u);
		c->SetMode(c->ci->WhoSends(), "BAN", mask);
		c->Kick(c->ci->WhoSends(), u, Language::Translate(u, _("Only members of %s may join this channel.")), only->c_str());
	}

	void OnChanInfo(CommandSource &source, ChannelInfo *ci, InfoFormatter &info, bool show_hidden) override
	{
		if (auto *only = grouponly.Get(ci))
			info[_("Group only")] = *only;
	}

	void OnNickInfo(CommandSource &source, NickAlias *na, InfoFormatter &info, bool show_hidden) override
	{
		Warden::string groups;
		const auto self = source.GetAccount() == na->nc;
		for (const auto &[name, g] : Groups)
		{
			auto *m = g->Find(na->nc);
			if (!m || m->flags.find('b') != Warden::string::npos)
				continue;
			if (!g->pub && !self && !show_hidden)
				continue;
			groups += (groups.empty() ? "" : " ") + name;
		}
		if (!groups.empty())
			info[_("Groups")] = groups;
	}
};

MODULE_INIT(GroupServCore)
