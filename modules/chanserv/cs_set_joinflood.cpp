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
// channel too quickly, it is made registered-users-only for a while (or, if
// the IRCd has no such mode, further unidentified joiners are banned and
// kicked until it ends). Based on genius3000's third-party cs_set_joinflood.

#include "module.h"

#define JOINFLOOD_EXT "JOINFLOOD"
#define JOINCOUNTER_EXT "joincounter"

struct JoinCounter final
{
	// Settings.
	unsigned joins = 3;
	time_t secs = 10;
	time_t duration = 60;

	// State.
	unsigned counter = 0;
	time_t reset = 0;
	bool engaged = false;
	bool setmode = false;
	std::vector<Warden::string> banmasks;

	JoinCounter(Extensible *) { }

	void ResetCounter()
	{
		this->reset = Warden::CurTime + this->secs;
		this->counter = 0;
	}
};

static ChannelMode *regonlymode = nullptr;

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

		// Only undo what we did: a +R that was there before stays.
		if (jc->setmode && regonlymode)
			c->RemoveMode(c->ci->WhoSends(), regonlymode);
		for (const auto &mask : jc->banmasks)
			c->RemoveMode(c->ci->WhoSends(), "BAN", mask);

		jc->engaged = false;
		jc->setmode = false;
		jc->banmasks.clear();
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

public:
	CommandCSSetJoinFlood(Module *creator, const Warden::string &cname = "chanserv/set/joinflood")
		: Command(creator, cname, 2, 5)
	{
		this->SetDesc(_("Make the channel registered-only during a join flood"));
		this->SetSyntax(_("\037channel\037 ON [\037joins\037 [\037time\037 [\037duration\037]]]"));
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
				source.Reply(_("Join flood protection in \002%s\002: %u joins within %s make it registered-only for %s."), ci->name.c_str(), jc->joins,
					Warden::Duration(jc->secs, source.GetAccount()).c_str(), Warden::Duration(jc->duration, source.GetAccount()).c_str());
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

			Log(source.AccessFor(ci).HasPriv("SET") ? LOG_COMMAND : LOG_OVERRIDE, source, this, ci) << "to enable join flood protection (" << joins << " joins in " << secs << "s, for " << duration << "s)";
			source.Reply(_("Join flood protection in \002%s\002 is now \002on\002: %u joins within %s make it registered-only for %s."), ci->name.c_str(), joins,
				Warden::Duration(secs, source.GetAccount()).c_str(), Warden::Duration(duration, source.GetAccount()).c_str());
		}
		else if (params[1].equals_ci("OFF"))
		{
			Log(source.AccessFor(ci).HasPriv("SET") ? LOG_COMMAND : LOG_OVERRIDE, source, this, ci) << "to disable join flood protection";
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
			"Protects the channel from join floods by unidentified users. When "
			"\037joins\037 of them join within \037time\037, the channel is made "
			"registered-users-only for \037duration\037, and the ops are told. If "
			"the IRCd has no such mode, unidentified users who join during that time "
			"are banned and kicked instead, and the bans are lifted afterwards."
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
		if (Me && Me->IsSynced())
			regonlymode = ModeManager::FindChannelModeByName("REGISTEREDONLY");
	}

	void OnUplinkSync(Server *) override
	{
		regonlymode = ModeManager::FindChannelModeByName("REGISTEREDONLY");
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
		if (!jc)
			return;

		// Engaged without a registered-only mode (or someone got in anyway):
		// keep unidentified users out until it ends.
		if (jc->engaged)
		{
			const auto mask = c->ci->GetIdealBan(u);
			jc->banmasks.push_back(mask);
			c->SetMode(c->ci->WhoSends(), "BAN", mask);
			c->Kick(c->ci->WhoSends(), u, "This channel is currently restricted to registered users only.");
			return;
		}

		if (jc->reset <= Warden::CurTime)
			jc->ResetCounter();
		if (++jc->counter < jc->joins)
			return;

		jc->engaged = true;
		if (regonlymode && !c->HasMode(regonlymode->name))
		{
			c->SetMode(c->ci->WhoSends(), regonlymode);
			jc->setmode = true;
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
