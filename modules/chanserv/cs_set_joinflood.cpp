// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2017 Matt Schatz (genius3000) <genius3000@g3k.solutions>
// Copyright (C) 2026 Warden Contributors
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// SPDX-License-Identifier: GPL-2.0-only

// A gentle join flood protection: when too many unidentified users join a
// channel too quickly, it sets some modes (+R by default) for a while and
// tells the ops. It never kicks or bans; that is left to the ops. Based on
// genius3000's third-party cs_set_joinflood.

#include "module.h"
#include "modules/chanserv/mode.h"

#define JOINFLOOD_EXT "JOINFLOOD"
#define JOINCOUNTER_EXT "joincounter"

struct JoinCounter final
{
	// Settings.
	unsigned joins = 3;
	time_t secs = 10;
	time_t duration = 60;
	Warden::string modes; // Mode letters; empty means the default.

	// State.
	unsigned counter = 0;
	time_t reset = 0;
	bool engaged = false;
	std::vector<Warden::string> setmodes; // Names of the modes we set.

	JoinCounter(Extensible *) { }

	void ResetCounter()
	{
		this->reset = Warden::CurTime + this->secs;
		this->counter = 0;
	}
};

// +R if the IRCd has it, +m otherwise.
static Warden::string DefaultModes()
{
	auto *cm = ModeManager::FindChannelModeByName("REGISTEREDONLY");
	return cm ? Warden::string(1, cm->mchar) : "m";
}

static Warden::string ModesOf(const JoinCounter *jc)
{
	return "+" + (jc->modes.empty() ? DefaultModes() : jc->modes);
}

// Sent to the channel's ops (with STATUSMSG) or the whole channel.
static void NoticeOps(Channel *c, const Warden::string &text)
{
	char symbol = 0;
	auto *cm = ModeManager::FindChannelModeByName("HALFOP");
	if (!cm)
		cm = ModeManager::FindChannelModeByName("OP");
	if (cm && cm->type == MODE_STATUS)
		symbol = static_cast<ChannelModeStatus *>(cm)->symbol;

	IRCD->SendNotice(c->ci->WhoSends(), (symbol ? Warden::string(1, symbol) : "") + c->name, text);
}

class DisengageTimer final
	: public Timer
{
	Warden::string channel;

public:
	DisengageTimer(Module *me, time_t seconds, Channel *c)
		: Timer(me, seconds)
		, channel(c->name)
	{
	}

	bool Tick() override
	{
		auto *c = Channel::Find(this->channel);
		if (!c || !c->ci)
			return false;

		auto *jc = c->ci->GetExt<JoinCounter>(JOINCOUNTER_EXT);
		if (!jc || !jc->engaged)
			return false;

		// Only undo what we did: modes that were set before stay.
		for (const auto &mode : jc->setmodes)
			c->RemoveMode(c->ci->WhoSends(), mode);

		jc->engaged = false;
		jc->setmodes.clear();
		jc->ResetCounter();

		NoticeOps(c, "Join flood protection has disengaged.");
		return false;
	}
};

class CommandCSSetJoinFlood final
	: public Command
{
	static bool ParseTime(const Warden::string &s, time_t &out)
	{
		out = Warden::DoTime(s);
		return out > 0;
	}

	// Checks "+Rm"-style input; returns the letters or an empty string.
	static Warden::string ParseModes(CommandSource &source, const Warden::string &input)
	{
		Warden::string letters;
		for (const auto chr : input)
		{
			if (chr == '+')
				continue;

			auto *cm = ModeManager::FindChannelModeByChar(chr);
			if (!cm)
			{
				source.Reply(_("This network has no channel mode \002%c\002."), chr);
				return "";
			}
			if (cm->type != MODE_REGULAR)
			{
				source.Reply(_("Mode \002%c\002 can't be used: only modes without a parameter, like \002R\002, \002i\002 or \002m\002."), chr);
				return "";
			}
			if (letters.find(chr) == Warden::string::npos)
				letters.push_back(chr);
		}
		if (letters.empty())
			source.Reply(_("Give the modes to set, such as \002+R\002 or \002+mR\002."));
		return letters;
	}

public:
	CommandCSSetJoinFlood(Module *creator, const Warden::string &cname = "chanserv/set/joinflood")
		: Command(creator, cname, 2, 5)
	{
		this->SetDesc(_("Set channel modes during a join flood"));
		this->SetSyntax(_("\037channel\037 ON [\037joins\037 [\037time\037 [\037duration\037]]]"));
		this->SetSyntax(_("\037channel\037 MODES \037modes\037"));
		this->SetSyntax(_("\037channel\037 OFF"));
		this->SetSyntax(_("\037channel\037 SHOW"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		auto *ci = ChannelInfo::Find(params[0]);
		if (!ci)
		{
			source.Reply(CHAN_X_NOT_REGISTERED, params[0].c_str());
			return;
		}

		if (params[1].equals_ci("SHOW"))
		{
			auto *jc = ci->GetExt<JoinCounter>(JOINCOUNTER_EXT);
			if (jc && ci->HasExt(JOINFLOOD_EXT))
				source.Reply(_("Join flood protection in \002%s\002: %u joins within %s set \002%s\002 for %s."), ci->name.c_str(), jc->joins,
					Warden::Duration(jc->secs, source.GetAccount()).c_str(), ModesOf(jc).c_str(), Warden::Duration(jc->duration, source.GetAccount()).c_str());
			else
				source.Reply(_("Join flood protection is not enabled for \002%s\002."), ci->name.c_str());
			return;
		}

		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
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

		const auto logtype = source.AccessFor(ci).HasPriv("SET") ? LOG_COMMAND : LOG_OVERRIDE;
		if (params[1].equals_ci("ON"))
		{
			unsigned joins = 3;
			time_t secs = 10, duration = 60;
			if (params.size() > 2)
			{
				const auto j = Warden::TryConvert<unsigned>(params[2]);
				if (!j || *j < 2 || (params.size() > 3 && !ParseTime(params[3], secs)) || (params.size() > 4 && !ParseTime(params[4], duration)))
				{
					source.Reply(_("Give at least 2 joins, and times such as \00210s\002 or \0022m\002."));
					return;
				}
				joins = *j;
			}

			ci->Extend<bool>(JOINFLOOD_EXT);
			auto *jc = ci->Require<JoinCounter>(JOINCOUNTER_EXT);
			jc->joins = joins;
			jc->secs = secs;
			jc->duration = duration;

			Log(logtype, source, this, ci) << "to enable join flood protection (" << joins << " joins in " << secs << "s, " << ModesOf(jc) << " for " << duration << "s)";
			source.Reply(_("Join flood protection in \002%s\002 is now \002on\002: %u joins within %s set \002%s\002 for %s."), ci->name.c_str(), joins,
				Warden::Duration(secs, source.GetAccount()).c_str(), ModesOf(jc).c_str(), Warden::Duration(duration, source.GetAccount()).c_str());
		}
		else if (params[1].equals_ci("MODES"))
		{
			if (params.size() < 3)
			{
				this->OnSyntaxError(source, "MODES");
				return;
			}

			const auto letters = ParseModes(source, params[2]);
			if (letters.empty())
				return;

			auto *jc = ci->Require<JoinCounter>(JOINCOUNTER_EXT);
			jc->modes = letters;
			Log(logtype, source, this, ci) << "to set the join flood modes to +" << letters;
			source.Reply(_("Join floods in \002%s\002 will set \002+%s\002."), ci->name.c_str(), letters.c_str());
		}
		else if (params[1].equals_ci("OFF"))
		{
			Log(logtype, source, this, ci) << "to disable join flood protection";
			ci->Shrink<bool>(JOINFLOOD_EXT);
			ci->Shrink<JoinCounter>(JOINCOUNTER_EXT);
			source.Reply(_("Join flood protection in \002%s\002 is now \002off\002."), ci->name.c_str());
		}
		else
			this->OnSyntaxError(source, "JOINFLOOD");
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Helps against join floods by unidentified users. When \037joins\037 of "
			"them join within \037time\037, the channel gets the join flood modes "
			"for \037duration\037 and the ops are told. Nobody is kicked or banned: "
			"what to do next is up to the ops. Afterwards only the modes it set are "
			"removed, and modes locked off with \002MODE LOCK\002 are never set."
			"\n\n"
			"\002MODES\002 chooses the modes, e.g. \002+mR\002 (moderated and "
			"registered-only). Only modes without a parameter can be used. The "
			"default is \002+R\002, or \002+m\002 on networks without +R."
			"\n\n"
			"The defaults are 3 joins within 10 seconds, for 60 seconds. Times can "
			"be given as seconds or like \00210s\002, \0022m\002 or \0021h\002. "
			"\002SHOW\002 shows the current settings."
		));
		return true;
	}
};

class CSSetJoinFlood final
	: public Module
{
	// Stores the settings with the channel.
	struct JoinFlood final
		: SerializableExtensibleItem<bool>
	{
		JoinFlood(Module *m, const Warden::string &n) : SerializableExtensibleItem<bool>(m, n) { }

		void ExtensibleSerialize(const Extensible *e, const Serializable *s, Serialize::Data &data) const override
		{
			SerializableExtensibleItem<bool>::ExtensibleSerialize(e, s, data);
			if (s->GetSerializableType()->GetName() != "ChannelInfo")
				return;

			const auto *ci = warden_dynamic_static_cast<const ChannelInfo *>(s);
			if (const auto *jc = ci->GetExt<JoinCounter>(JOINCOUNTER_EXT))
			{
				data.Store("jf:joins", jc->joins);
				data.Store("jf:secs", jc->secs);
				data.Store("jf:duration", jc->duration);
				data.Store("jf:modes", jc->modes);
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

			auto *jc = ci->Require<JoinCounter>(JOINCOUNTER_EXT);
			jc->joins = data.Load<unsigned>("jf:joins");
			jc->secs = data.Load<time_t>("jf:secs");
			jc->duration = data.Load<time_t>("jf:duration");
			jc->modes = data.Load<Warden::string>("jf:modes");
		}
	} joinflood;

	ExtensibleItem<JoinCounter> joincounter;
	CommandCSSetJoinFlood commandcssetjoinflood;

public:
	CSSetJoinFlood(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, VENDOR)
		, joinflood(this, JOINFLOOD_EXT)
		, joincounter(this, JOINCOUNTER_EXT)
		, commandcssetjoinflood(this)
	{
	}

	void OnJoinChannel(User *u, Channel *c) override
	{
		if (Me && !Me->IsSynced())
			return;
		if (!c->ci || !joinflood.HasExt(c->ci))
			return;
		if (u->IsIdentified() || u->server->IsULined() || !u->server->IsSynced())
			return;

		auto *jc = c->ci->GetExt<JoinCounter>(JOINCOUNTER_EXT);
		if (!jc || jc->engaged)
			return;

		if (jc->reset <= Warden::CurTime)
			jc->ResetCounter();
		if (++jc->counter < jc->joins)
			return;

		jc->engaged = true;
		const auto *locks = c->ci->GetExt<ChanServ::ModeLocks>(CHANSERV_MODE_LOCK_EXT);
		for (const auto chr : ModesOf(jc).substr(1))
		{
			auto *cm = ModeManager::FindChannelModeByChar(chr);
			if (!cm || cm->type != MODE_REGULAR || c->HasMode(cm->name))
				continue;
			if (locks && locks->HasMLock(cm, "", false))
				continue; // Locked off: don't fight the mode lock.

			c->SetMode(c->ci->WhoSends(), cm);
			jc->setmodes.push_back(cm->name);
		}
		new DisengageTimer(this, jc->duration, c);
		NoticeOps(c, "Join flood protection has engaged for " + Warden::Duration(jc->duration) + ".");
	}

	void OnChanInfo(CommandSource &source, ChannelInfo *ci, InfoFormatter &info, bool show_hidden) override
	{
		if (show_hidden && joinflood.HasExt(ci))
			info.AddOption(_("Join flood protection"));
	}
};

MODULE_INIT(CSSetJoinFlood)
