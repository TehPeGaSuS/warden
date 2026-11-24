// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2010 Atheme Project (http://atheme.org/)
// Copyright (C) 2026 Warden Contributors
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// SPDX-License-Identifier: GPL-2.0-only

// ChanFix: remembers who usually has ops in *unregistered* channels and can
// give them back when a channel loses all its ops (or is taken over). The
// scoring and fixing follow Atheme's chanfix; ideas also from reverse's
// third-party Anope ChanFix. Registered channels are left to ChanServ.

#include "module.h"

#define CHANFIX_TYPE "ChanFixChannel"

namespace
{
	// Atheme's constants.
	const unsigned OP_THRESHOLD = 3;     // Channels with this many ops are fine.
	const float ACCOUNT_WEIGHT = 1.5f;   // Identified ops count for more.
	const float INITIAL_STEP = 0.70f;    // A fix starts opping at 70% of the best score...
	const float FINAL_STEP = 0.30f;      // ...and goes down to 30% over fixtime.
	const unsigned EXPIRE_DIVISOR = 672; // Scores fade by 1/672 an hour (about 4 weeks).

	struct Settings final
	{
		time_t gather = 300, expire = 3600, autofix_interval = 60, fixtime = 3600, retention = 28 * 86400;
		unsigned minfixscore = 12, minusers = 0, listmax = 50;
		bool autofix = false, clearmodes = true, restrictregister = false;
		std::vector<Warden::string> exclude;
	} conf;

	struct OpRecord final
	{
		uint64_t account = 0; // 0 if they were never seen identified.
		Warden::string user, host;
		time_t firstseen = 0, lastevent = 0;
		unsigned age = 1;

		unsigned Score() const
		{
			return account ? static_cast<unsigned>(age * ACCOUNT_WEIGHT) : age;
		}

		Warden::string Who() const
		{
			if (account)
				if (auto *nc = NickCore::FindId(account))
					return nc->display;
			return user + "@" + host;
		}
	};
}

struct FixChannel final
	: Serializable
{
	Warden::string name;
	time_t ts = 0, lastupdate = 0;
	std::vector<OpRecord> ops;
	Warden::string marksetter, markreason, nofixsetter, nofixreason;
	time_t marktime = 0, nofixtime = 0;

	// Not saved.
	time_t fix_started = 0;
	bool fix_requested = false;

	FixChannel() : Serializable(CHANFIX_TYPE) { }
	~FixChannel() override;

	// Atheme: the same account, or the same user@host.
	OpRecord *Find(const User *u)
	{
		auto *nc = u->Account();
		for (auto &op : ops)
		{
			if (op.account && nc && op.account == nc->GetId())
				return &op;
			if (op.user.equals_ci(u->GetIdent()) && op.host.equals_ci(u->GetDisplayedHost()))
				return &op;
		}
		return nullptr;
	}

	unsigned HighScore() const
	{
		unsigned high = 0;
		for (const auto &op : ops)
			high = std::max(high, op.Score());
		return high;
	}

	unsigned Threshold() const
	{
		auto t = Warden::CurTime - fix_started;
		if (t > conf.fixtime)
			t = conf.fixtime;
		const auto step = INITIAL_STEP + (FINAL_STEP - INITIAL_STEP) * (conf.fixtime ? static_cast<float>(t) / conf.fixtime : 1.0f);
		return std::max(1u, static_cast<unsigned>(HighScore() * step));
	}
};

static Warden::map<FixChannel *> FixChannels;

FixChannel::~FixChannel()
{
	FixChannels.erase(this->name);
}

struct FixChannelType final
	: Serialize::Type
{
	FixChannelType() : Serialize::Type(CHANFIX_TYPE) { }

	void Serialize(Serializable *obj, Serialize::Data &data) const override
	{
		const auto *fc = static_cast<const FixChannel *>(obj);
		data.Store("name", fc->name);
		data.Store("ts", fc->ts);
		data.Store("lastupdate", fc->lastupdate);
		data.Store("marksetter", fc->marksetter);
		data.Store("markreason", fc->markreason);
		data.Store("marktime", fc->marktime);
		data.Store("nofixsetter", fc->nofixsetter);
		data.Store("nofixreason", fc->nofixreason);
		data.Store("nofixtime", fc->nofixtime);

		// One op per line: account user host firstseen lastevent age.
		std::stringstream ops;
		for (const auto &op : fc->ops)
			ops << op.account << " " << op.user << " " << op.host << " " << op.firstseen << " " << op.lastevent << " " << op.age << "\n";
		data.Store("ops", ops.str());
	}

	Serializable *Unserialize(Serializable *obj, Serialize::Data &data) const override
	{
		auto *fc = obj ? warden_dynamic_static_cast<FixChannel *>(obj) : new FixChannel();
		if (!obj)
		{
			fc->name = data.Load("name");
			if (fc->name.empty() || FixChannels.count(fc->name))
			{
				delete fc;
				return nullptr;
			}
			FixChannels[fc->name] = fc;
		}

		fc->ts = data.Load<time_t>("ts");
		fc->lastupdate = data.Load<time_t>("lastupdate");
		fc->marksetter = data.Load("marksetter");
		fc->markreason = data.Load("markreason");
		fc->marktime = data.Load<time_t>("marktime");
		fc->nofixsetter = data.Load("nofixsetter");
		fc->nofixreason = data.Load("nofixreason");
		fc->nofixtime = data.Load<time_t>("nofixtime");

		fc->ops.clear();
		sepstream lines(data.Load("ops"), '\n');
		for (Warden::string line; lines.GetToken(line); )
		{
			spacesepstream fields(line);
			Warden::string account, user, host, firstseen, lastevent, age;
			if (!fields.GetToken(account) || !fields.GetToken(user) || !fields.GetToken(host) || !fields.GetToken(firstseen) || !fields.GetToken(lastevent) || !fields.GetToken(age))
				continue;
			OpRecord op;
			op.account = Warden::Convert<uint64_t>(account, 0);
			op.user = user;
			op.host = host;
			op.firstseen = Warden::Convert<time_t>(firstseen, 0);
			op.lastevent = Warden::Convert<time_t>(lastevent, 0);
			op.age = Warden::Convert<unsigned>(age, 1);
			fc->ops.push_back(op);
		}
		return fc;
	}
};

static FixChannel *Get(const Warden::string &name)
{
	auto it = FixChannels.find(name);
	return it == FixChannels.end() ? nullptr : it->second;
}

static FixChannel *GetOrCreate(Channel *c)
{
	if (auto *fc = Get(c->name))
		return fc;
	auto *fc = new FixChannel();
	fc->name = c->name;
	fc->ts = c->created;
	fc->lastupdate = Warden::CurTime;
	FixChannels[fc->name] = fc;
	return fc;
}

static bool IsOp(const Membership *cu)
{
	for (const auto *mode : cu->status.Modes())
		if (mode->name == "OP" || mode->name == "PROTECT" || mode->name == "OWNER")
			return true;
	return false;
}

static unsigned CountOps(Channel *c)
{
	unsigned n = 0;
	for (const auto &[_, cu] : c->users)
		if (IsOp(cu))
			++n;
	return n;
}

static bool Tracked(Channel *c)
{
	if (c->ci || c->name.empty())
		return false;
	for (const auto &mask : conf.exclude)
	{
		if (Warden::Match(c->name, mask))
			return false;
	}
	return c->users.size() >= conf.minusers;
}

class ChanFixCore;
static Reference<BotInfo> ChanFix;

// Atheme's chanfix_should_handle.
static bool ShouldHandle(FixChannel *fc, Channel *c)
{
	if (!c || c->ci || !fc->nofixsetter.empty())
		return false;
	const auto ops = CountOps(c);
	if (ops >= OP_THRESHOLD)
		return false;
	if (ops > 0 && (!fc->fix_started || Warden::CurTime - fc->fix_started > conf.fixtime))
		return false;
	return true;
}

// Ops everyone at or above the current threshold. Returns how many.
static unsigned FixChannel_(FixChannel *fc, Channel *c)
{
	const auto threshold = fc->Threshold();
	unsigned opped = 0;
	for (const auto &[_, cu] : c->users)
	{
		auto *u = cu->user;
		if (u->server == Me || IsOp(cu))
			continue;
		auto *op = fc->Find(u);
		if (op && op->Score() >= threshold)
		{
			c->SetMode(*ChanFix, "OP", u->GetUID());
			++opped;
		}
	}
	if (opped)
		Log(LOG_NORMAL, "chanfix/fix", *ChanFix) << "Opped " << opped << " user(s) in " << c->name << " (threshold " << threshold << ")";
	return opped;
}

static bool CanStartFix(FixChannel *fc, Channel *c)
{
	const auto threshold = static_cast<unsigned>(fc->HighScore() * FINAL_STEP);
	for (const auto &[_, cu] : c->users)
	{
		if (cu->user->server == Me)
			continue;
		if (IsOp(cu))
			return false;
		auto *op = fc->Find(cu->user);
		if (op && op->Score() >= threshold)
			return true;
	}
	return false;
}

// Removes +i, +l, +k and bans so the right people can get back in. Only done
// while a fix is in progress.
static void ClearModes(Channel *c)
{
	if (!conf.clearmodes)
		return;
	for (const auto *mode : { "INVITE", "LIMIT" })
		if (c->HasMode(mode))
			c->RemoveMode(*ChanFix, mode);
	Warden::string key;
	if (c->GetParam("KEY", key))
		c->RemoveMode(*ChanFix, "KEY", key);
	for (const auto &ban : c->GetModeList("BAN"))
		c->RemoveMode(*ChanFix, "BAN", ban);
}

// Atheme's chanfix_lower_ts: re-creating the channel with an older TS makes
// the IRCd drop every op and mode, undoing a takeover.
static void LowerTS(FixChannel *fc, Channel *c)
{
	fc->ts = std::min(fc->ts ? fc->ts : c->created, c->created) - 1;
	c->created = fc->ts;
	IRCD->SendChannel(c);
	c->Reset();
}

static void AutoFix()
{
	for (auto it = FixChannels.begin(); it != FixChannels.end(); )
	{
		auto *fc = (it++)->second;
		if (!conf.autofix && !fc->fix_requested)
			continue;

		auto *c = Channel::Find(fc->name);
		if (!ShouldHandle(fc, c))
		{
			fc->fix_requested = false;
			fc->fix_started = 0;
			continue;
		}

		if (!fc->fix_started)
		{
			// Automatic fixes need real history, like a CHANFIX by an oper does.
			if (!fc->fix_requested && fc->HighScore() < conf.minfixscore)
				continue;
			if (!CanStartFix(fc, c))
			{
				// Only clear modes for a fix someone asked for.
				if (fc->fix_requested)
					ClearModes(c);
				continue;
			}
			Log(LOG_NORMAL, "chanfix/fix", *ChanFix) << "Fixing " << c->name << (fc->fix_requested ? "" : " automatically");
			fc->fix_started = Warden::CurTime;
			if (!FixChannel_(fc, c))
				ClearModes(c);
		}
		else if (!FixChannel_(fc, c) && !CountOps(c))
			ClearModes(c);
	}
}

static void Gather()
{
	for (const auto &[_, c] : ChannelList)
	{
		if (!Tracked(c))
			continue;

		FixChannel *fc = nullptr;
		for (const auto &[__, cu] : c->users)
		{
			auto *u = cu->user;
			if (!IsOp(cu) || u->server == Me || u->server->IsULined())
				continue;

			// Only channels that have had ops get a record.
			if (!fc)
				fc = GetOrCreate(c);

			auto *op = fc->Find(u);
			if (op)
			{
				op->age++;
				op->lastevent = Warden::CurTime;
				if (!op->account && u->Account())
					op->account = u->Account()->GetId();
			}
			else
			{
				OpRecord rec;
				rec.account = u->Account() ? u->Account()->GetId() : 0;
				rec.user = u->GetIdent();
				rec.host = u->GetDisplayedHost();
				rec.firstseen = rec.lastevent = Warden::CurTime;
				fc->ops.push_back(rec);
				fc->lastupdate = Warden::CurTime;
			}
		}
		if (fc)
		{
			// Seen with ops now: a channel whose ops never change still counts
			// as active, or it would be forgotten after the retention period.
			fc->lastupdate = Warden::CurTime;
			fc->QueueUpdate();
		}
	}
}

static void Expire()
{
	for (auto it = FixChannels.begin(); it != FixChannels.end(); )
	{
		auto *fc = (it++)->second;
		auto &ops = fc->ops;
		for (auto &op : ops)
			op.age -= (op.age + EXPIRE_DIVISOR - 1) / EXPIRE_DIVISOR;
		ops.erase(std::remove_if(ops.begin(), ops.end(), [](const auto &op) {
			return !op.age || Warden::CurTime - op.lastevent >= conf.retention;
		}), ops.end());
		fc->QueueUpdate();

		// Marked and NOFIX channels are kept for staff.
		const auto keep = !fc->marksetter.empty() || !fc->nofixsetter.empty();
		if (!keep && (ops.empty() || Warden::CurTime - fc->lastupdate >= conf.retention))
			delete fc;
	}
}

class ChanFixTimer final
	: public Timer
{
	void (*func)();

public:
	ChanFixTimer(Module *m, time_t interval, void (*f)()) : Timer(m, interval), func(f) { }

	bool Tick() override
	{
		if (Me && Me->IsSynced())
			func();
		return true; // Keep repeating.
	}
};

static FixChannel *Lookup(CommandSource &source, const Warden::string &name)
{
	auto *fc = Get(name);
	if (fc)
		return fc;

	if (ChannelInfo::Find(name))
		source.Reply(_("\002%s\002 is registered; ChanFix only tracks unregistered channels."), name.c_str());
	else
		source.Reply(_("There is no ChanFix record for \002%s\002 (yet)."), name.c_str());
	return nullptr;
}

class CommandCFChanFix final
	: public Command
{
public:
	CommandCFChanFix(Module *creator) : Command(creator, "chanfix/chanfix", 1, 1)
	{
		this->SetDesc(_("Give a channel's usual ops back"));
		this->SetSyntax(_("\037channel\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		auto *c = Channel::Find(params[0]);
		if (!c)
		{
			source.Reply(CHAN_X_NOT_IN_USE, params[0].c_str());
			return;
		}
		if (c->ci)
		{
			source.Reply(_("\002%s\002 is registered, so ChanFix leaves it to ChanServ."), c->name.c_str());
			return;
		}
		auto *fc = Lookup(source, c->name);
		if (!fc)
			return;
		if (!fc->nofixsetter.empty())
		{
			source.Reply(_("\002%s\002 has NOFIX set."), c->name.c_str());
			return;
		}
		if (fc->HighScore() < conf.minfixscore)
		{
			source.Reply(_("The scores for \002%s\002 are too low (under %u) for a fix."), c->name.c_str(), conf.minfixscore);
			return;
		}

		LowerTS(fc, c);
		fc->fix_requested = true;
		fc->fix_started = 0;
		Log(LOG_ADMIN, source, this) << "on " << c->name;
		source.Reply(_("Fixing \002%s\002: everyone's ops and modes have been removed, and its usual ops will get theirs back over the next %s."),
			c->name.c_str(), Warden::Duration(conf.fixtime, source.GetAccount()).c_str());
		AutoFix();
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Fixes an unregistered channel that has lost its ops or been taken "
			"over. The channel's timestamp is lowered, which makes the IRCd remove "
			"everyone's ops and modes; then the people who usually had ops there "
			"(the highest scores) get them back, starting with the best and "
			"lowering the bar over time until someone is opped."
		));
		return true;
	}
};

class CommandCFScores final
	: public Command
{
public:
	CommandCFScores(Module *creator) : Command(creator, "chanfix/scores", 1, 2)
	{
		this->SetDesc(_("Show a channel's op scores"));
		this->SetSyntax(_("\037channel\037 [\037count\037]"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		auto *fc = Lookup(source, params[0]);
		if (!fc)
			return;
		if (fc->ops.empty())
		{
			source.Reply(_("There are no scores for \002%s\002."), fc->name.c_str());
			return;
		}

		auto count = params.size() > 1 ? Warden::Convert<unsigned>(params[1], 20) : 20;
		std::vector<const OpRecord *> sorted;
		for (const auto &op : fc->ops)
			sorted.push_back(&op);
		std::sort(sorted.begin(), sorted.end(), [](const auto *a, const auto *b) { return a->Score() > b->Score(); });
		count = std::min<unsigned>(count, sorted.size());

		ListFormatter list(source.GetAccount());
		list.AddColumn(_("Number")).AddColumn(_("Account/Mask")).AddColumn(_("Score"));
		for (unsigned i = 0; i < count; ++i)
		{
			ListFormatter::ListEntry entry;
			entry["Number"] = Warden::ToString(i + 1);
			entry["Account/Mask"] = sorted[i]->Who();
			entry["Score"] = Warden::ToString(sorted[i]->Score());
			list.AddEntry(entry);
		}
		source.Reply(_("Top %u scores for \002%s\002:"), count, fc->name.c_str());
		list.SendTo(source);
		source.Reply(_("End of scores for \002%s\002."), fc->name.c_str());
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Shows the highest op scores in a channel (20 by default). A score grows every few minutes someone has ops there, counts 1.5 times as much for identified users, and slowly fades."));
		return true;
	}
};

class CommandCFInfo final
	: public Command
{
public:
	CommandCFInfo(Module *creator) : Command(creator, "chanfix/info", 1, 1)
	{
		this->SetDesc(_("Show ChanFix information about a channel"));
		this->SetSyntax(_("\037channel\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		auto *fc = Lookup(source, params[0]);
		if (!fc)
			return;

		auto *c = Channel::Find(fc->name);
		const auto high = fc->HighScore();
		InfoFormatter info(source.GetAccount());
		info[_("Created")] = fc->ts ? Warden::strftime(fc->ts, source.GetAccount()) : "?";
		info[_("Highest score")] = Warden::ToString(high);
		info[_("Ops tracked")] = Warden::ToString(fc->ops.size());
		info[_("Users")] = c ? Warden::ToString(c->users.size()) : "0";
		info[_("Needs fixing")] = ShouldHandle(fc, c) ? source.Translate(_("Yes")) : source.Translate(_("No"));
		info[_("Being fixed")] = fc->fix_started ? source.Translate(_("Yes")) : source.Translate(_("No"));
		if (fc->fix_started)
			info[_("Current threshold")] = Warden::ToString(fc->Threshold());
		if (!fc->marksetter.empty())
			info[_("Marked")] = Warden::Format(source.Translate(_("by %s on %s: %s")), fc->marksetter.c_str(), Warden::strftime(fc->marktime, source.GetAccount(), true).c_str(), fc->markreason.c_str());
		if (!fc->nofixsetter.empty())
			info[_("NOFIX")] = Warden::Format(source.Translate(_("by %s on %s: %s")), fc->nofixsetter.c_str(), Warden::strftime(fc->nofixtime, source.GetAccount(), true).c_str(), fc->nofixreason.c_str());

		source.Reply(_("ChanFix information about \002%s\002:"), fc->name.c_str());
		info.SendTo(source);
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Shows what ChanFix knows about a channel: its highest score, whether it needs or is getting a fix, and any MARK or NOFIX."));
		return true;
	}
};

class CommandCFList final
	: public Command
{
public:
	CommandCFList(Module *creator) : Command(creator, "chanfix/list", 0, 1)
	{
		this->SetDesc(_("List the channels ChanFix tracks"));
		this->SetSyntax(_("[\037pattern\037]"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		const auto pattern = params.empty() ? "*" : params[0];
		ListFormatter list(source.GetAccount());
		list.AddColumn(_("Channel")).AddColumn(_("Highest score")).AddColumn(_("Notes"));
		unsigned matches = 0;
		for (const auto &[name, fc] : FixChannels)
		{
			if (!Warden::Match(name, pattern))
				continue;
			if (++matches > conf.listmax)
				continue;
			ListFormatter::ListEntry entry;
			entry["Channel"] = name;
			entry["Highest score"] = Warden::ToString(fc->HighScore());
			Warden::string notes;
			if (!fc->marksetter.empty())
				notes += "MARKED ";
			if (!fc->nofixsetter.empty())
				notes += "NOFIX";
			entry["Notes"] = notes;
			list.AddEntry(entry);
		}
		if (!matches)
		{
			source.Reply(_("No tracked channels match \002%s\002."), pattern.c_str());
			return;
		}
		source.Reply(_("Tracked channels matching \002%s\002:"), pattern.c_str());
		list.SendTo(source);
		source.Reply(_("End of list - %u/%u shown."), std::min(matches, conf.listmax), matches);
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Lists the channels ChanFix has scores for, matching a pattern."));
		return true;
	}
};

// MARK and NOFIX: a note for staff, and a block on fixing.
class CommandCFNote final
	: public Command
{
	bool nofix;

public:
	CommandCFNote(Module *creator, bool nf) : Command(creator, nf ? "chanfix/nofix" : "chanfix/mark", 2, 3), nofix(nf)
	{
		if (nofix)
			this->SetDesc(_("Stop ChanFix from fixing a channel"));
		else
			this->SetDesc(_("Leave a note on a channel for staff"));
		this->SetSyntax(_("\037channel\037 {ON \037reason\037 | OFF}"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		auto *fc = Get(params[0]);
		auto &setter = nofix ? (fc ? fc->nofixsetter : setter_dummy) : (fc ? fc->marksetter : setter_dummy);
		const auto what = nofix ? "NOFIX" : "MARK";

		if (params[1].equals_ci("ON"))
		{
			if (params.size() < 3)
			{
				this->OnSyntaxError(source, "");
				return;
			}
			if (!fc)
			{
				// Staff may note a channel ChanFix hasn't seen ops in yet.
				auto *c = Channel::Find(params[0]);
				if (!c)
				{
					source.Reply(CHAN_X_NOT_IN_USE, params[0].c_str());
					return;
				}
				fc = GetOrCreate(c);
			}
			(nofix ? fc->nofixsetter : fc->marksetter) = source.GetNick();
			(nofix ? fc->nofixreason : fc->markreason) = params[2];
			(nofix ? fc->nofixtime : fc->marktime) = Warden::CurTime;
			fc->QueueUpdate();
			Log(LOG_ADMIN, source, this) << "ON on " << fc->name << ": " << params[2];
			source.Reply(_("%s is now set on \002%s\002."), what, fc->name.c_str());
		}
		else if (params[1].equals_ci("OFF"))
		{
			if (!fc || setter.empty())
			{
				source.Reply(_("%s is not set on \002%s\002."), what, params[0].c_str());
				return;
			}
			(nofix ? fc->nofixsetter : fc->marksetter).clear();
			(nofix ? fc->nofixreason : fc->markreason).clear();
			fc->QueueUpdate();
			Log(LOG_ADMIN, source, this) << "OFF on " << fc->name;
			source.Reply(_("%s is no longer set on \002%s\002."), what, fc->name.c_str());
		}
		else
			this->OnSyntaxError(source, "");
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		if (nofix)
			source.Reply(_("Stops ChanFix from fixing the channel, with a reason other staff can see in \002INFO\002."));
		else
			source.Reply(_("Leaves a note on the channel that other staff see in \002INFO\002 and \002LIST\002."));
		return true;
	}

private:
	static inline Warden::string setter_dummy;
};

class ChanFixCore final
	: public Module
{
	FixChannelType fixchanneltype;
	CommandCFChanFix commandcfchanfix;
	CommandCFScores commandcfscores;
	CommandCFInfo commandcfinfo;
	CommandCFList commandcflist;
	CommandCFNote commandcfmark, commandcfnofix;
	std::vector<ChanFixTimer *> timers;

	void StartTimers()
	{
		for (auto *t : timers)
			delete t;
		timers = {
			new ChanFixTimer(this, conf.gather, Gather),
			new ChanFixTimer(this, conf.expire, Expire),
			new ChanFixTimer(this, conf.autofix_interval, AutoFix),
		};
	}

public:
	ChanFixCore(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, PSEUDOCLIENT | VENDOR)
		, commandcfchanfix(this), commandcfscores(this), commandcfinfo(this), commandcflist(this)
		, commandcfmark(this, false), commandcfnofix(this, true)
	{
	}

	~ChanFixCore() override
	{
		for (auto *t : timers)
			delete t;
		for (auto it = FixChannels.begin(); it != FixChannels.end(); )
			delete (it++)->second;
	}

	void OnReload(Configuration::Conf &config) override
	{
		const auto &block = config.GetModule(this);
		const auto &nick = block.Get<const Warden::string>("client");
		if (nick.empty())
			throw ConfigException(Module::name + ": <client> must be defined");
		auto *bi = BotInfo::Find(nick, true);
		if (!bi)
			throw ConfigException(Module::name + ": no bot named " + nick);
		ChanFix = bi;

		conf.gather = std::max<time_t>(60, block.Get<time_t>("gatherinterval", "5m"));
		conf.fixtime = std::max<time_t>(60, block.Get<time_t>("fixtime", "1h"));
		conf.retention = std::max<time_t>(86400, block.Get<time_t>("retention", "28d"));
		conf.minfixscore = block.Get<unsigned>("minfixscore", "12");
		conf.minusers = block.Get<unsigned>("minusers", "0");
		conf.listmax = block.Get<unsigned>("listmax", "50");
		conf.autofix = block.Get<bool>("autofix", "no");
		conf.clearmodes = block.Get<bool>("clearmodes", "yes");
		conf.restrictregister = block.Get<bool>("restrictregister", "no");
		conf.exclude.clear();
		commasepstream excludes(block.Get<const Warden::string>("exclude"), true);
		for (Warden::string list; excludes.GetToken(list);)
		{
			spacesepstream masks(list);
			for (Warden::string mask; masks.GetToken(mask);)
				conf.exclude.push_back(mask);
		}
		StartTimers();
	}

	EventReturn OnPreHelp(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		if (!params.empty() || source.c || source.service != *ChanFix)
			return EVENT_CONTINUE;
		source.Reply(_("\002%s\002 remembers who usually has ops in unregistered channels, and can give them back when a channel loses its ops or is taken over."), ChanFix->nick.c_str());
		source.Reply(" ");
		return EVENT_CONTINUE;
	}

	// Optionally, people with a low score can't register a channel that
	// others usually run (Atheme's chanfix_can_register).
	EventReturn OnPreCommand(CommandSource &source, Command *command, std::vector<Warden::string> &params) override
	{
		if (!conf.restrictregister || command->name != "chanserv/register" || params.empty() || !source.GetUser())
			return EVENT_CONTINUE;
		auto *fc = Get(params[0]);
		if (!fc || source.HasPriv("chanserv/administration"))
			return EVENT_CONTINUE;
		const auto high = fc->HighScore();
		if (high < conf.minfixscore)
			return EVENT_CONTINUE;
		auto *op = fc->Find(source.GetUser());
		if (op && op->Score() >= high * FINAL_STEP)
			return EVENT_CONTINUE;
		source.Reply(_("Your ChanFix score is too low to register \002%s\002; ask one of its usual ops to do it."), params[0].c_str());
		return EVENT_STOP;
	}
};

MODULE_INIT(ChanFixCore)
