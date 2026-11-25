// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2015 Fill <filipe@codinghighway.com>
// Copyright (C) 2026 Warden Contributors
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// SPDX-License-Identifier: GPL-2.0-only

// Keeps a channel's user limit (+l) a little above the number of users in it,
// so a flood of joins (clones, a botnet) is held back while normal users can
// still get in. Based on Fill's third-party cs_autolimit (GPL-1.0-or-later).

#include "module.h"
#include "modules/chanserv/mode.h"

#define AUTOLIMIT_EXT "AUTOLIMIT"
#define AUTOLIMIT_DATA_EXT "autolimit"

namespace
{
	const unsigned MIN_AMOUNT = 1, MAX_AMOUNT = 100;
	const time_t MIN_INTERVAL = 10, MAX_INTERVAL = 3600;
	const time_t TIMER_INTERVAL = 5;
}

struct AutoLimit final
{
	unsigned amount = 5;
	time_t interval = 30;
	Warden::string setter;

	// When the limit was last checked.
	time_t last_check = 0;

	AutoLimit(Extensible *) { }
};

// Whether a mode lock on the channel fixes or forbids +l, so the limit is
// not ours to manage.
static bool LimitLocked(ChannelInfo *ci)
{
	auto *locks = ci->GetExt<ChanServ::ModeLocks>(CHANSERV_MODE_LOCK_EXT);
	return locks && locks->GetMLock("LIMIT");
}

// Sets the limit to the user count plus the amount, if it differs.
static void Update(Channel *c, AutoLimit *al)
{
	if (!c->ci || LimitLocked(c->ci))
		return;

	const auto limit = Warden::ToString(c->users.size() + al->amount);
	Warden::string current;
	if (c->GetParam("LIMIT", current) && current == limit)
		return; // Only send a mode when the limit changes.

	c->SetMode(c->ci->WhoSends(), "LIMIT", limit);
}

class CommandCSAutoLimit final
	: public Command
{
	static void Report(CommandSource &source, const ChannelInfo *ci, const AutoLimit *al)
	{
		source.Reply(_("\002%s\002: user count + %u, checked every %s (set by %s)."), ci->name.c_str(), al->amount,
			Warden::Duration(al->interval, source.GetAccount()).c_str(), al->setter.c_str());
	}

public:
	CommandCSAutoLimit(Module *creator)
		: Command(creator, "chanserv/autolimit", 1, 4)
	{
		this->SetDesc(_("Keep the channel's user limit just above its user count"));
		this->SetSyntax(_("\037channel\037 SET \037amount\037 \037interval\037"));
		this->SetSyntax(_("\037channel\037 {DEL | SHOW}"));
		this->SetSyntax(_("LIST"), [](auto &source) { return source.HasPriv("chanserv/administration"); });
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		if (params[0].equals_ci("LIST"))
		{
			if (!source.HasPriv("chanserv/administration"))
			{
				source.Reply(ACCESS_DENIED);
				return;
			}

			unsigned count = 0;
			for (const auto &[_, ci] : *RegisteredChannelList)
			{
				const auto *al = ci->GetExt<AutoLimit>(AUTOLIMIT_DATA_EXT);
				if (!al || !ci->HasExt(AUTOLIMIT_EXT))
					continue;
				Report(source, ci, al);
				++count;
			}
			if (!count)
				source.Reply(_("No channel has an automatic user limit."));
			else
				source.Reply(_("End of list - %u channels."), count);
			return;
		}

		if (params.size() < 2)
		{
			this->OnSyntaxError(source, "");
			return;
		}

		auto *ci = ChannelInfo::Find(params[0]);
		if (!ci)
		{
			source.Reply(CHAN_X_NOT_REGISTERED, params[0].c_str());
			return;
		}

		// Its own privilege, or SET with a chanserv.conf from before it existed.
		const auto *priv = PrivilegeManager::FindPrivilege("AUTOLIMIT") ? "AUTOLIMIT" : "SET";
		const auto access = source.AccessFor(ci).HasPriv(priv);
		if (!access && !source.HasPriv("chanserv/administration"))
		{
			source.Reply(ACCESS_DENIED);
			return;
		}

		const auto option = params[1].upper();
		if (option == "SHOW")
		{
			const auto *al = ci->GetExt<AutoLimit>(AUTOLIMIT_DATA_EXT);
			if (al && ci->HasExt(AUTOLIMIT_EXT))
				Report(source, ci, al);
			else
				source.Reply(_("\002%s\002 has no automatic user limit."), ci->name.c_str());
			return;
		}

		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		if (option == "SET")
		{
			if (params.size() < 4)
			{
				this->OnSyntaxError(source, "SET");
				return;
			}

			const auto amount = Warden::TryConvert<unsigned>(params[2]);
			if (!amount || *amount < MIN_AMOUNT || *amount > MAX_AMOUNT)
			{
				source.Reply(_("The amount must be between %u and %u."), MIN_AMOUNT, MAX_AMOUNT);
				return;
			}

			const auto interval = Warden::DoTime(params[3]);
			if (interval < MIN_INTERVAL || interval > MAX_INTERVAL)
			{
				source.Reply(_("The interval must be between %s and %s, e.g. \00230s\002 or \0022m\002."),
					Warden::Duration(MIN_INTERVAL, source.GetAccount()).c_str(), Warden::Duration(MAX_INTERVAL, source.GetAccount()).c_str());
				return;
			}

			if (LimitLocked(ci))
			{
				source.Reply(_("The user limit of \002%s\002 is mode locked; remove that lock first."), ci->name.c_str());
				return;
			}

			ci->Extend<bool>(AUTOLIMIT_EXT);
			auto *al = ci->Require<AutoLimit>(AUTOLIMIT_DATA_EXT);
			al->amount = *amount;
			al->interval = interval;
			al->setter = source.GetNick();
			al->last_check = Warden::CurTime;
			if (ci->c)
				Update(ci->c, al);

			Log(access ? LOG_COMMAND : LOG_OVERRIDE, source, this, ci) << "to set the automatic user limit to the user count + " << *amount << " every " << interval << "s";
			source.Reply(_("The user limit of \002%s\002 will be kept at the user count + %u, checked every %s."), ci->name.c_str(), *amount,
				Warden::Duration(interval, source.GetAccount()).c_str());
		}
		else if (option == "DEL")
		{
			if (!ci->HasExt(AUTOLIMIT_EXT))
			{
				source.Reply(_("\002%s\002 has no automatic user limit."), ci->name.c_str());
				return;
			}

			ci->Shrink<bool>(AUTOLIMIT_EXT);
			ci->Shrink<AutoLimit>(AUTOLIMIT_DATA_EXT);
			if (ci->c && ci->c->HasMode("LIMIT") && !LimitLocked(ci))
				ci->c->RemoveMode(ci->WhoSends(), "LIMIT");

			Log(access ? LOG_COMMAND : LOG_OVERRIDE, source, this, ci) << "to remove the automatic user limit";
			source.Reply(_("The automatic user limit of \002%s\002 has been removed."), ci->name.c_str());
		}
		else
			this->OnSyntaxError(source, "");
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Keeps the channel's user limit (+l) a little above the number of "
			"users in it, so a flood of joins is held back while people can "
			"still get in. Every \037interval\037 the limit is set to the user "
			"count plus \037amount\037, but only when that changes it."
			"\n\n"
			"A large interval or a small amount may keep people out during or "
			"after a netsplit; an amount of 5 to 10 checked every 30 seconds is "
			"a good start. The interval can be given in seconds or like "
			"\00230s\002 or \0022m\002."
			"\n\n"
			"\002DEL\002 stops it and removes the limit. \002SHOW\002 shows the "
			"settings. A mode lock on the limit (+l or -l) takes precedence."
			"\n\n"
			"You need the \002AUTOLIMIT\002 privilege on the channel (see \002LEVELS\002)."
		));
		if (source.HasPriv("chanserv/administration"))
		{
			source.Reply(" ");
			source.Reply(_("Services Operators can use it on any channel, and \002LIST\002 shows every channel with an automatic user limit."));
		}
		return true;
	}
};

class AutoLimitTimer final
	: public Timer
{
public:
	AutoLimitTimer(Module *m)
		: Timer(m, TIMER_INTERVAL)
	{
	}

	bool Tick() override
	{
		if (!Me || !Me->IsSynced())
			return true;

		for (const auto &[_, c] : ChannelList)
		{
			if (!c->ci || !c->ci->HasExt(AUTOLIMIT_EXT))
				continue;
			auto *al = c->ci->GetExt<AutoLimit>(AUTOLIMIT_DATA_EXT);
			if (!al || al->last_check + al->interval > Warden::CurTime)
				continue;
			al->last_check = Warden::CurTime;
			Update(c, al);
		}
		return true;
	}
};

class CSAutoLimit final
	: public Module
{
	// Stores the settings with the channel.
	struct AutoLimitItem final
		: SerializableExtensibleItem<bool>
	{
		AutoLimitItem(Module *m, const Warden::string &n) : SerializableExtensibleItem<bool>(m, n) { }

		void ExtensibleSerialize(const Extensible *e, const Serializable *s, Serialize::Data &data) const override
		{
			SerializableExtensibleItem<bool>::ExtensibleSerialize(e, s, data);
			if (s->GetSerializableType()->GetName() != "ChannelInfo")
				return;

			const auto *ci = warden_dynamic_static_cast<const ChannelInfo *>(s);
			if (const auto *al = ci->GetExt<AutoLimit>(AUTOLIMIT_DATA_EXT))
			{
				data.Store("al:amount", al->amount);
				data.Store("al:interval", al->interval);
				data.Store("al:setter", al->setter);
			}
		}

		void ExtensibleUnserialize(Extensible *e, Serializable *s, Serialize::Data &data) override
		{
			SerializableExtensibleItem<bool>::ExtensibleUnserialize(e, s, data);
			if (s->GetSerializableType()->GetName() != "ChannelInfo")
				return;

			auto *ci = warden_dynamic_static_cast<ChannelInfo *>(s);
			if (!this->HasExt(ci))
				return;

			auto *al = ci->Require<AutoLimit>(AUTOLIMIT_DATA_EXT);
			al->amount = std::clamp(data.Load<unsigned>("al:amount"), MIN_AMOUNT, MAX_AMOUNT);
			al->interval = std::clamp(data.Load<time_t>("al:interval"), MIN_INTERVAL, MAX_INTERVAL);
			al->setter = data.Load("al:setter");
		}
	} autolimit;

	ExtensibleItem<AutoLimit> autolimitdata;
	CommandCSAutoLimit commandcsautolimit;
	AutoLimitTimer timer;

public:
	CSAutoLimit(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, VENDOR)
		, autolimit(this, AUTOLIMIT_EXT)
		, autolimitdata(this, AUTOLIMIT_DATA_EXT)
		, commandcsautolimit(this)
		, timer(this)
	{
	}

	void OnChanInfo(CommandSource &source, ChannelInfo *ci, InfoFormatter &info, bool show_hidden) override
	{
		const auto *al = ci->GetExt<AutoLimit>(AUTOLIMIT_DATA_EXT);
		if (show_hidden && al && autolimit.HasExt(ci))
			info[_("Automatic limit")] = Warden::Format(Language::Translate(source.GetAccount(), _("user count + %u, every %s")),
				al->amount, Warden::Duration(al->interval, source.GetAccount()).c_str());
	}
};

MODULE_INIT(CSAutoLimit)
