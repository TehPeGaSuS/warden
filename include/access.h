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

#include "services.h"
#include "warden.h"
#include "serialize.h"
#include "service.h"

enum
{
	ACCESS_INVALID = -10000,
	ACCESS_FOUNDER = 10001
};

/* A privilege, probably configured using a privilege{} block. Most
 * commands require specific privileges to be executed. The AccessProvider
 * backing each ChanAccess determines whether that ChanAccess has a given
 * privilege.
 */
struct CoreExport Privilege final
{
	Warden::string name;
	Warden::string desc;
	/* Rank relative to other privileges */
	int rank;

	Privilege(const Warden::string &name, const Warden::string &desc, int rank);
	bool operator==(const Privilege &other) const;
};

class CoreExport PrivilegeManager final
{
	static std::vector<Privilege> Privileges;
public:
	static void AddPrivilege(Privilege p);
	static void RemovePrivilege(Privilege &p);
	static Privilege *FindPrivilege(const Warden::string &name);
	static std::vector<Privilege> &GetPrivileges();
	static void ClearPrivileges();
};

/* A provider of access. Only used for creating ChanAccesses, as
 * they contain pure virtual functions.
 */
class CoreExport AccessProvider
	: public Service
{
public:
	AccessProvider(Module *owner, const Warden::string &name);
	virtual ~AccessProvider();

	/** Creates a new ChanAccess entry using this provider.
	 * @return The new entry
	 */
	virtual ChanAccess *Create() = 0;

	virtual void GetAccess(CommandSource& source, const Privilege *p, Warden::map<Warden::string> &access) = 0;
	static void SendAccess(CommandSource &source, const Warden::string &pname);

private:
	static std::list<AccessProvider *> Providers;
public:
	static const std::list<AccessProvider *>& GetProviders();
};

/* Represents one entry of an access list on a channel. */
class CoreExport ChanAccess
	: public Serializable
{
public:
	struct Type final
		: public Serialize::Type
	{
		Type();
		void Serialize(Serializable *obj, Serialize::Data &data) const override;
		Serializable *Unserialize(Serializable *obj, Serialize::Data &data) const override;
	};

private:
	Warden::string mask;
	/* account this access entry is for, if any */
	Serialize::Reference<NickCore> nc;

public:
	typedef std::vector<ChanAccess *> Path;

	/* The provider that created this access entry */
	AccessProvider *provider;
	/* Channel this access entry is on */
	Serialize::Reference<ChannelInfo> ci;
	Warden::string creator;
	Warden::string description;
	time_t last_seen;
	time_t created;

	ChanAccess(AccessProvider *p);
	virtual ~ChanAccess();

	void SetMask(const Warden::string &mask, ChannelInfo *ci);
	const Warden::string &Mask() const;
	NickCore *GetAccount() const;

	static const unsigned int MAX_DEPTH = 4;

	/** Check if this access entry matches the given user or account
	 * @param u The user
	 * @param nc The account
	 * @param next Next channel to check if any
	 */
	virtual bool Matches(const User *u, const NickCore *nc, ChannelInfo *&next) const;

	/** Check if this access entry has the given privilege.
	 * @param name The privilege name
	 */
	virtual bool HasPriv(const Warden::string &name) const = 0;

	/** Serialize the access given by this access entry into a human
	 * readable form. chanserv/access will return a number, chanserv/xop
	 * will be AOP, SOP, etc.
	 */
	virtual Warden::string AccessSerialize() const = 0;

	/** Unserialize this access entry from the given data. This data
	 * will be fetched from AccessSerialize.
	 */
	virtual void AccessUnserialize(const Warden::string &data) = 0;

	/* Comparison operators to other Access entries */
	virtual bool operator>(const ChanAccess &other) const;
	virtual bool operator<(const ChanAccess &other) const;
	bool operator>=(const ChanAccess &other) const;
	bool operator<=(const ChanAccess &other) const;
};

/* A group of access entries. This is used commonly, for example with ChannelInfo::AccessFor,
 * to show what access a user has on a channel because users can match multiple access entries.
 */
class CoreExport AccessGroup final
{
public:
	/* access entries + paths */
	std::vector<ChanAccess::Path> paths;
	/* Channel these access entries are on */
	const ChannelInfo *ci;
	/* Account these entries affect, if any */
	const NickCore *nc;
	/* super_admin always gets all privs. founder is a special case where ci->founder == nc */
	bool super_admin, founder;

	AccessGroup();

	/** Check if this access group has a certain privilege. Eg, it
	 * will check every ChanAccess entry of this group for any that
	 * has the given privilege.
	 * @param priv The privilege
	 * @return true if any entry has the given privilege
	 */
	bool HasPriv(const Warden::string &priv) const;

	/** Get the "highest" access entry from this group of entries.
	 * The highest entry is determined by the entry that has the privilege
	 * with the highest rank (see Privilege::rank).
	 * @return The "highest" entry
	 */
	const ChanAccess *Highest() const;

	/* Comparison operators to other AccessGroups */
	bool operator>(const AccessGroup &other) const;
	bool operator<(const AccessGroup &other) const;
	bool operator>=(const AccessGroup &other) const;
	bool operator<=(const AccessGroup &other) const;

	inline bool empty() const { return paths.empty(); }
};
