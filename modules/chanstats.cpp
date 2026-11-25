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

#include "module.h"
#include "modules/sql.h"

class CommandCSSetChanstats final
	: public Command
{
public:
	CommandCSSetChanstats(Module *creator) : Command(creator, "chanserv/set/chanstats", 2, 2)
	{
		this->SetDesc(_("Turn chanstats statistics on or off"));
		this->SetSyntax(_("\037channel\037 {ON | OFF}"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		ChannelInfo *ci = ChannelInfo::Find(params[0]);
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

		if (params[1].equals_ci("ON"))
		{
			ci->Extend<bool>("CS_STATS");
			source.Reply(_("Chanstats statistics are now enabled for \002%s\002."), ci->name.c_str());
			Log(source.AccessFor(ci).HasPriv("SET") ? LOG_COMMAND : LOG_OVERRIDE, source, this, ci) << "to enable chanstats";
		}
		else if (params[1].equals_ci("OFF"))
		{
			Log(source.AccessFor(ci).HasPriv("SET") ? LOG_COMMAND : LOG_OVERRIDE, source, this, ci) << "to disable chanstats";
			ci->Shrink<bool>("CS_STATS");
			source.Reply(_("Chanstats statistics are now disabled for \002%s\002."), ci->name.c_str());
		}
		else
			this->OnSyntaxError(source, "");
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Turns chanstats statistics ON or OFF."));
		return true;
	}
};

class CommandNSSetChanstats
	: public Command
{
public:
	CommandNSSetChanstats(Module *creator, const Warden::string &sname = "nickserv/set/chanstats", size_t min = 1 ) : Command(creator, sname, min, min + 1)
	{
		this->SetDesc(_("Turn chanstats statistics on or off"));
		this->SetSyntax("{ON | OFF}");
	}
	void Run(CommandSource &source, const Warden::string &user, const Warden::string &param, bool saset = false)
	{
		NickAlias *na = NickAlias::Find(user);
		if (!na)
		{
			source.Reply(NICK_X_NOT_REGISTERED, user.c_str());
			return;
		}

		EventReturn MOD_RESULT;
		FOREACH_RESULT(OnSetNickOption, MOD_RESULT, (source, this, na->nc, param));
		if (MOD_RESULT == EVENT_STOP)
			return;

		if (param.equals_ci("ON"))
		{
			Log(na->nc == source.GetAccount() ? LOG_COMMAND : LOG_ADMIN, source, this) << "to enable chanstats for " << na->nc->display;
			na->nc->Extend<bool>("NS_STATS");
			if (saset)
				source.Reply(_("Chanstats statistics are now enabled for \002%s\002."), na->nc->display.c_str());
			else
				source.Reply(_("Chanstats statistics are now enabled for your nick."));
		}
		else if (param.equals_ci("OFF"))
		{
			Log(na->nc == source.GetAccount() ? LOG_COMMAND : LOG_ADMIN, source, this) << "to disable chanstats for " << na->nc->display;
			na->nc->Shrink<bool>("NS_STATS");
			if (saset)
				source.Reply(_("Chanstats statistics are now disabled for \002%s\002."), na->nc->display.c_str());
			else
				source.Reply(_("Chanstats statistics are now disabled for your nick."));
		}
		else
			this->OnSyntaxError(source, "CHANSTATS");
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		this->Run(source, source.nc->display, params[0]);
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Turns chanstats statistics ON or OFF."));
		return true;
	}
};

class CommandNSSASetChanstats final
	: public CommandNSSetChanstats
{
public:
	CommandNSSASetChanstats(Module *creator) : CommandNSSetChanstats(creator, "nickserv/saset/chanstats", 2)
	{
		this->ClearSyntax();
		this->SetSyntax(_("\037nickname\037 {ON | OFF}"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		this->Run(source, params[0], params[1], true);
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("Turns chanstats channel statistics ON or OFF for this user."));
		return true;
	}
};

class SQLInterface final
	: public SQL::Interface
{
public:
	SQLInterface(Module *o) : SQL::Interface(o) { }

	void OnResult(const SQL::Result &r) override
	{
	}

	void OnError(const SQL::Result &r) override
	{
		if (!r.GetQuery().query.empty())
			Log(LOG_DEBUG) << "Chanstats: Error executing query " << r.finished_query << ": " << r.GetError();
		else
			Log(LOG_DEBUG) << "Chanstats: Error executing query: " << r.GetError();
	}
};

/** Runs a follow-up query once the first one succeeded, then deletes itself. */
class MergeInterface final
	: public SQL::Interface
{
	ServiceReference<SQL::Provider> sql;
	SQL::Query next;
	SQL::Interface *after;

public:
	MergeInterface(Module *o, const ServiceReference<SQL::Provider> &s, const SQL::Query &n, SQL::Interface *a) : SQL::Interface(o), sql(s), next(n), after(a) { }

	void OnResult(const SQL::Result &r) override
	{
		if (sql)
			sql->Run(after, next);
		delete this;
	}

	void OnError(const SQL::Result &r) override
	{
		Log(this->owner) << "Unable to move the statistics to the new display name, the old rows were kept: " << r.GetError();
		delete this;
	}
};

class MChanstats final
	: public Module
{
	SerializableExtensibleItem<bool> cs_stats, ns_stats;

	CommandCSSetChanstats commandcssetchanstats;

	CommandNSSetChanstats commandnssetchanstats;
	CommandNSSASetChanstats commandnssasetchanstats;

	ServiceReference<SQL::Provider> sql;
	SQLInterface sqlinterface;
	SQL::Query query;
	Warden::string SmileysHappy, SmileysSad, SmileysOther, prefix;
	// The engine to copy the statistics from when our table is new.
	Warden::string convert_from;

	/* The counters that are added up for every row. */
	static const std::vector<Warden::string> &Counters()
	{
		static std::vector<Warden::string> counters;
		if (counters.empty())
		{
			counters = { "letters", "words", "line", "actions", "smileys_happy", "smileys_sad",
				"smileys_other", "kicks", "kicked", "modes", "topics" };
			for (int i = 0; i < 24; ++i)
				counters.push_back("time" + Warden::ToString(i));
		}
		return counters;
	}

	/* The period each reset type is currently in, as last written to the
	 * resets table. A reset happens when the current period differs.
	 */
	std::map<Warden::string, Warden::string> periods;

	class ResetTimer final
		: public Timer
	{
		MChanstats *mod;

	public:
		ResetTimer(MChanstats *m) : Timer(m, 60), mod(m)
		{
			this->SetSecs(60);
		}

		bool Tick() override
		{
			mod->CheckResets(false);
			return true;
		}
	};
	ResetTimer *resettimer = nullptr;

	void RunQuery(const SQL::Query &q)
	{
		if (sql)
			sql->Run(&sqlinterface, q);
	}

	static size_t CountWords(const Warden::string &msg)
	{
		size_t words = 0;
		for (size_t pos = 0; pos != Warden::string::npos; pos = msg.find(" ", pos+1))
			words++;
		return words;
	}
	static size_t CountSmileys(const Warden::string &msg, const Warden::string &smileylist)
	{
		size_t smileys = 0;
		spacesepstream sep(smileylist);
		Warden::string buf;

		while (sep.GetToken(buf) && !buf.empty())
		{
			for (size_t pos = msg.find(buf, 0); pos != Warden::string::npos; pos = msg.find(buf, pos+1))
				smileys++;
		}
		return smileys;
	}

	Warden::string GetDisplay(User *u)
	{
		if (u && u->IsIdentified() && ns_stats.HasExt(u->Account()))
			return u->Account()->display;
		else
			return "";
	}

	Warden::string Driver()
	{
		return sql ? sql->GetDriver() : "";
	}

	/** Builds "INSERT ... that skips rows that already exist". */
	Warden::string InsertIgnore(const Warden::string &table, const Warden::string &rest)
	{
		if (Driver() == "mysql")
			return "INSERT IGNORE INTO `" + table + "` " + rest;
		return "INSERT INTO `" + table + "` " + rest + " ON CONFLICT DO NOTHING";
	}

	/** Adds the given amounts to the channel, the user and the user's global rows. */
	void Update(const Warden::string &channel, const Warden::string &nick, const std::map<Warden::string, size_t> &values)
	{
		if (!sql)
			return;

		const auto table = prefix + "chanstats";

		// Make sure all the rows exist.
		SQL::Query ins(InsertIgnore(table, "(`nick`, `chan`, `type`) VALUES "
			"('', @chan@, 'total'), ('', @chan@, 'monthly'), ('', @chan@, 'weekly'), ('', @chan@, 'daily')"));
		ins.SetValue("chan", channel);
		this->RunQuery(ins);

		if (!nick.empty())
		{
			ins = InsertIgnore(table, "(`nick`, `chan`, `type`) VALUES "
				"(@nick@, @chan@, 'total'), (@nick@, @chan@, 'monthly'), (@nick@, @chan@, 'weekly'), (@nick@, @chan@, 'daily'), "
				"(@nick@, '', 'total'), (@nick@, '', 'monthly'), (@nick@, '', 'weekly'), (@nick@, '', 'daily')");
			ins.SetValue("chan", channel);
			ins.SetValue("nick", nick);
			this->RunQuery(ins);
		}

		Warden::string set;
		for (const auto &[column, value] : values)
		{
			if (!set.empty())
				set += ", ";
			set += "`" + column + "` = `" + column + "` + " + Warden::ToString(value);
		}
		if (set.empty())
			return;

		SQL::Query upd("UPDATE `" + table + "` SET " + set + " WHERE (`nick` = '' OR `nick` = @nick@) AND (`chan` = '' OR `chan` = @chan@)");
		upd.SetValue("chan", channel);
		upd.SetValue("nick", nick);
		this->RunQuery(upd);
	}

	static Warden::string HourColumn()
	{
		const time_t now = Warden::CurTime;
		return "time" + Warden::ToString(localtime(&now)->tm_hour);
	}

	/** The period that a reset type is in right now, in local time. Weeks
	 * start on Sunday, like the MySQL events Anope used to create.
	 */
	static Warden::string CurrentPeriod(const Warden::string &type)
	{
		time_t now = Warden::CurTime;
		struct tm tm = *localtime(&now);
		char buf[32];
		if (type == "monthly")
			strftime(buf, sizeof(buf), "%Y-%m", &tm);
		else if (type == "weekly")
		{
			now -= tm.tm_wday * 86400;
			tm = *localtime(&now);
			strftime(buf, sizeof(buf), "%Y-%m-%d", &tm);
		}
		else
			strftime(buf, sizeof(buf), "%Y-%m-%d", &tm);
		return buf;
	}

	/** Zeroes the daily, weekly and monthly rows when their period changed,
	 * including any period that passed while Warden was not running.
	 */
	void CheckResets(bool startup)
	{
		if (!sql)
			return;

		const auto table = prefix + "chanstats";
		const auto resets = prefix + "chanstats_resets";
		for (const auto *type : { "daily", "weekly", "monthly" })
		{
			const auto period = CurrentPeriod(type);
			auto it = this->periods.find(type);
			if (it != this->periods.end() && it->second == period)
				continue;

			// The first time (a new table, or one that MySQL events used to
			// reset) only records the period.
			if (it != this->periods.end())
			{
				Warden::string set;
				for (const auto &column : Counters())
					set += (set.empty() ? "`" : ", `") + column + "` = 0";
				SQL::Query reset("UPDATE `" + table + "` SET " + set + " WHERE `type` = @type@");
				reset.SetValue("type", Warden::string(type));
				this->RunQuery(reset);
				Log(LOG_DEBUG) << "chanstats: " << type << " statistics reset (" << it->second << " -> " << period << ")";
			}
			else if (!startup)
				continue;

			SQL::Query mark;
			if (Driver() == "postgresql")
				mark = "INSERT INTO `" + resets + "` (`type`, `period`) VALUES (@type@, @period@) ON CONFLICT (`type`) DO UPDATE SET `period` = EXCLUDED.`period`";
			else
				mark = "REPLACE INTO `" + resets + "` (`type`, `period`) VALUES (@type@, @period@)";
			mark.SetValue("type", Warden::string(type));
			mark.SetValue("period", period);
			this->RunQuery(mark);

			this->periods[type] = period;
		}
	}

	void CheckTables()
	{
		const auto driver = Driver();
		const auto table = prefix + "chanstats";
		const auto resets = prefix + "chanstats_resets";

		std::set<Warden::string> tables;
		SQL::Result r = this->sql->RunQuery(this->sql->GetTables(prefix));
		for (int i = 0; i < r.Rows(); ++i)
		{
			for (const auto &[_, name] : r.Row(i))
				tables.insert(name);
		}

		Warden::string counters;
		for (const auto &column : Counters())
		{
			const auto big = column == "letters" || column == "words";
			if (driver == "mysql")
				counters += ", `" + column + "` " + (big ? "bigint" : "int") + " unsigned NOT NULL DEFAULT '0'";
			else
				counters += ", `" + column + "` BIGINT NOT NULL DEFAULT 0";
		}

		const bool fresh = !tables.count(table);
		if (fresh)
		{
			if (driver == "mysql")
			{
				this->RunQuery("CREATE TABLE `" + table + "` ("
					"`id` int NOT NULL AUTO_INCREMENT,"
					"`chan` varchar(64) NOT NULL DEFAULT '',"
					"`nick` varchar(64) NOT NULL DEFAULT '',"
					"`type` ENUM('total', 'monthly', 'weekly', 'daily') NOT NULL" + counters + ","
					"PRIMARY KEY (`id`),"
					"UNIQUE KEY `chan` (`chan`,`nick`,`type`),"
					"KEY `nick` (`nick`),"
					"KEY `chan_` (`chan`),"
					"KEY `type` (`type`)"
					") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
			}
			else
			{
				const Warden::string id = driver == "postgresql" ? "`id` BIGSERIAL PRIMARY KEY" : "`id` INTEGER PRIMARY KEY";
				this->RunQuery("CREATE TABLE `" + table + "` (" + id + ","
					"`chan` TEXT NOT NULL DEFAULT '',"
					"`nick` TEXT NOT NULL DEFAULT '',"
					"`type` VARCHAR(16) NOT NULL CHECK (`type` IN ('total', 'monthly', 'weekly', 'daily'))" + counters + ","
					"UNIQUE (`chan`, `nick`, `type`))");
				this->RunQuery("CREATE INDEX `" + table + "_nick` ON `" + table + "` (`nick`)");
				this->RunQuery("CREATE INDEX `" + table + "_type` ON `" + table + "` (`type`)");
			}
		}

		if (!tables.count(resets))
			this->RunQuery("CREATE TABLE `" + resets + "` (`type` VARCHAR(16) NOT NULL PRIMARY KEY, `period` VARCHAR(16) NOT NULL)");

		if (driver == "mysql")
		{
			// Anope used stored procedures and MySQL events; Warden does the
			// same work itself, so remove them (the events would reset the
			// statistics a second time).
			for (const auto *event : { "chanstats_event_cleanup_daily", "chanstats_event_cleanup_weekly", "chanstats_event_cleanup_monthly" })
				this->RunQuery(Warden::string("DROP EVENT IF EXISTS `") + event + "`");
			for (const auto *proc : { "chanstats_proc_update", "chanstats_proc_chgdisplay" })
				this->RunQuery("DROP PROCEDURE IF EXISTS `" + prefix + proc + "`");
		}

		this->periods.clear();
		r = this->sql->RunQuery("SELECT `type`, `period` FROM `" + resets + "`");
		for (int i = 0; i < r.Rows(); ++i)
			this->periods[r.Get(i, "type")] = r.Get(i, "period");

		if (!this->convert_from.empty())
		{
			if (fresh)
				this->Convert();
			else
				Log(this) << "The statistics table already exists, so convert_from is ignored. You can remove it from the configuration.";
		}

		this->CheckResets(true);
	}

	/* Copies the statistics from the convert_from engine into our new
	 * table. The inserts are queued behind the CREATE TABLE.
	 */
	void Convert()
	{
		ServiceReference<SQL::Provider> source("SQL::Provider", this->convert_from);
		if (!source)
		{
			Log(this) << "Unable to copy the statistics, is SQL (" << this->convert_from << ") configured correctly?";
			return;
		}

		const auto table = prefix + "chanstats";
		Warden::string columns = "`chan`, `nick`, `type`";
		for (const auto &column : Counters())
			columns += ", `" + column + "`";

		const int chunk = 500;
		size_t copied = 0;
		for (int offset = 0; ; offset += chunk)
		{
			SQL::Result r = source->RunQuery("SELECT " + columns + " FROM `" + table + "` ORDER BY `id` LIMIT " + Warden::ToString(chunk) + " OFFSET " + Warden::ToString(offset));
			if (!r.GetError().empty())
			{
				Log(this) << "Unable to read the statistics from " << this->convert_from << ": " << r.GetError();
				break;
			}

			for (int i = 0; i < r.Rows(); i += 100)
			{
				SQL::Query ins("INSERT INTO `" + table + "` (" + columns + ") VALUES ");
				for (int j = i; j < r.Rows() && j < i + 100; ++j)
				{
					const auto row = "r" + Warden::ToString(j - i) + "_";
					ins.query += (j == i ? "(" : ", (");
					ins.query += "@" + row + "chan@, @" + row + "nick@, @" + row + "type@";
					ins.SetValue(row + "chan", r.Get(j, "chan"));
					ins.SetValue(row + "nick", r.Get(j, "nick"));
					ins.SetValue(row + "type", r.Get(j, "type"));
					for (const auto &column : Counters())
					{
						ins.query += ", @" + row + column + "@";
						ins.SetValue(row + column, Warden::TryConvert<uint64_t>(r.Get(j, column)).value_or(0));
					}
					ins.query += ")";
					++copied;
				}
				this->RunQuery(ins);
			}

			if (r.Rows() < chunk)
				break;
		}

		// Keep the reset periods too, so nothing is reset twice or skipped.
		SQL::Result r = source->RunQuery("SELECT `type`, `period` FROM `" + prefix + "chanstats_resets`");
		for (int i = 0; i < r.Rows(); ++i)
		{
			SQL::Query mark("INSERT INTO `" + prefix + "chanstats_resets` (`type`, `period`) VALUES (@type@, @period@)");
			mark.SetValue("type", r.Get(i, "type"));
			mark.SetValue("period", r.Get(i, "period"));
			this->RunQuery(mark);
			this->periods[r.Get(i, "type")] = r.Get(i, "period");
		}

		Log(this) << "Copied " << copied << " statistics rows from " << this->convert_from << ". You can remove convert_from from the configuration.";
	}

public:
	MChanstats(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, EXTRA | VENDOR)
		, cs_stats(this, "CS_STATS")
		, ns_stats(this, "NS_STATS")
		, commandcssetchanstats(this)
		, commandnssetchanstats(this)
		, commandnssasetchanstats(this)
		, sql("SQL::Provider")
		, sqlinterface(this)
	{
	}

	~MChanstats()
	{
		delete this->resettimer;
	}

	void OnReload(Configuration::Conf &conf) override
	{
		const auto &block = conf.GetModule(this);
		prefix = block.Get<const Warden::string>("prefix", "chanstats21_");
		SmileysHappy = block.Get<const Warden::string>("SmileysHappy");
		SmileysSad = block.Get<const Warden::string>("SmileysSad");
		SmileysOther = block.Get<const Warden::string>("SmileysOther");
		convert_from = block.Get<const Warden::string>("convert_from");
		this->sql.SetServiceName(block.Get<const Warden::string>("engine"));
		if (sql)
		{
			this->CheckTables();
			if (!this->resettimer)
				this->resettimer = new ResetTimer(this);
		}
		else
			Log(this) << "no database connection to " << this->sql.GetServiceName();
	}

	void OnChanInfo(CommandSource &source, ChannelInfo *ci, InfoFormatter &info, bool show_all) override
	{
		if (!show_all)
			return;
		if (cs_stats.HasExt(ci))
			info.AddOption(_("Chanstats"));
	}

	void OnNickInfo(CommandSource &source, NickAlias *na, InfoFormatter &info, bool show_hidden) override
	{
		if (!show_hidden)
			return;
		if (ns_stats.HasExt(na->nc))
			info.AddOption(_("Chanstats"));
	}

	void OnTopicUpdated(User *source, Channel *c, const Warden::string &user, const Warden::string &topic) override
	{
		if (!source || !source->IsIdentified() || !c->ci || !cs_stats.HasExt(c->ci))
			return;
		this->Update(c->name, GetDisplay(source), { { "topics", 1 } });
	}

	EventReturn OnChannelModeSet(Channel *c, MessageSource &setter, ChannelMode *mode, const ModeData &data) override
	{
		this->OnModeChange(c, setter.GetUser());
		return EVENT_CONTINUE;
	}

	EventReturn OnChannelModeUnset(Channel *c, MessageSource &setter, ChannelMode *, const Warden::string &param) override
	{
		this->OnModeChange(c, setter.GetUser());
		return EVENT_CONTINUE;
	}

private:
	void OnModeChange(Channel *c, User *u)
	{
		if (!u || !u->IsIdentified() || !c->ci || !cs_stats.HasExt(c->ci))
			return;

		this->Update(c->name, GetDisplay(u), { { "modes", 1 } });
	}

public:
	void OnPreUserKicked(const MessageSource &source, Membership *memb, const Warden::string &kickmsg) override
	{
		if (!memb->chan->ci || !cs_stats.HasExt(memb->chan->ci))
			return;

		this->Update(memb->chan->name, GetDisplay(memb->user), { { "kicked", 1 } });
		this->Update(memb->chan->name, GetDisplay(source.GetUser()), { { "kicks", 1 } });
	}

	void OnPrivmsg(User *u, Channel *c, Warden::string &msg, const Warden::map<Warden::string> &tags) override
	{
		if (!c->ci || !cs_stats.HasExt(c->ci))
			return;

		size_t letters = msg.length();
		size_t words = this->CountWords(msg);

		size_t action = 0;
		if (msg.find("\01ACTION")!=Warden::string::npos)
		{
			action = 1;
			letters = letters - 7;
			words--;
		}

		// count smileys
		size_t smileys_happy = CountSmileys(msg, SmileysHappy);
		size_t smileys_sad = CountSmileys(msg, SmileysSad);
		size_t smileys_other = CountSmileys(msg, SmileysOther);

		// do not count smileys as words
		size_t smileys = smileys_happy + smileys_sad + smileys_other;
		if (smileys > words)
			words = 0;
		else
			words = words - smileys;

		this->Update(c->name, GetDisplay(u), {
			{ "line", 1 },
			{ HourColumn(), 1 },
			{ "letters", letters },
			{ "words", words },
			{ "actions", action },
			{ "smileys_happy", smileys_happy },
			{ "smileys_sad", smileys_sad },
			{ "smileys_other", smileys_other },
		});
	}

	void OnDelCore(NickCore *nc) override
	{
		query = "DELETE FROM `" + prefix + "chanstats` WHERE `nick` = @nick@;";
		query.SetValue("nick", nc->display);
		this->RunQuery(query);
	}

	void OnChangeCoreDisplay(NickCore *nc, const Warden::string &newdisplay) override
	{
		if (!sql)
			return;

		// Move the old display's rows to the new one, adding them to any rows
		// the new display already has.
		const auto table = prefix + "chanstats";
		Warden::string columns, update;
		for (const auto &column : Counters())
		{
			columns += ", `" + column + "`";
			if (!update.empty())
				update += ", ";
			if (Driver() == "mysql")
				update += "`" + column + "` = `" + table + "`.`" + column + "` + VALUES(`" + column + "`)";
			else
				update += "`" + column + "` = `" + table + "`.`" + column + "` + EXCLUDED.`" + column + "`";
		}

		query = "INSERT INTO `" + table + "` (`chan`, `nick`, `type`" + columns + ") "
			"SELECT `chan`, @new_display@, `type`" + columns + " FROM `" + table + "` AS `src` WHERE `nick` = @old_display@";
		if (Driver() == "mysql")
			query.query += " ON DUPLICATE KEY UPDATE " + update;
		else
			query.query += " ON CONFLICT (`chan`, `nick`, `type`) DO UPDATE SET " + update;
		query.SetValue("old_display", nc->display);
		query.SetValue("new_display", newdisplay);

		// Only delete the old rows once they have been copied.
		SQL::Query del("DELETE FROM `" + table + "` WHERE `nick` = @old_display@");
		del.SetValue("old_display", nc->display);
		sql->Run(new MergeInterface(this, sql, del, &sqlinterface), query);
	}

	void OnDelChan(ChannelInfo *ci) override
	{
		query = "DELETE FROM `" + prefix + "chanstats` WHERE `chan` = @channel@;";
		query.SetValue("channel", ci->name);
		this->RunQuery(query);
	}
};

MODULE_INIT(MChanstats)
