// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2017 genius3000 <genius3000@g3k.solutions>
// Copyright (C) 2026 Warden Contributors
//
// Warden is free software. You can use, modify, and/or distribute it under the
// terms of version 2 of the GNU General Public License. See docs/LICENSE.txt
// for the complete terms of this license and docs/AUTHORS.txt for a list of
// contributors.
//
// SPDX-License-Identifier: GPL-2.0-only

// Keeps the last few topics of each channel that turns it on, so they can be
// listed and put back. Based on genius3000's third-party cs_topichistory.

#include "module.h"

#define TOPICHISTORY_TYPE "TopicHistory"
#define TOPICHISTORY_LIST_EXT "topichistorylist"

struct TopicHistoryEntry final
	: Serializable
{
	Warden::string chan;
	Warden::string topic;
	Warden::string setter;
	time_t when = 0;

	TopicHistoryEntry()
		: Serializable(TOPICHISTORY_TYPE)
	{
	}

	TopicHistoryEntry(ChannelInfo *c, const Warden::string &ctopic, const Warden::string &csetter, time_t ctime = Warden::CurTime)
		: Serializable(TOPICHISTORY_TYPE)
		, chan(c->name)
		, topic(ctopic)
		, setter(csetter)
		, when(ctime)
	{
	}

	~TopicHistoryEntry() override;
};

// A channel's entries, newest first. Entry 0 is the current topic.
struct TopicHistoryList final
	: Serialize::Checker<std::vector<TopicHistoryEntry *>>
{
	TopicHistoryList(Extensible *)
		: Serialize::Checker<std::vector<TopicHistoryEntry *>>(TOPICHISTORY_TYPE)
	{
	}

	~TopicHistoryList()
	{
		for (auto i = (*this)->size(); i > 0; --i)
			delete (*this)->at(i - 1);
	}
};

TopicHistoryEntry::~TopicHistoryEntry()
{
	auto *ci = ChannelInfo::Find(this->chan);
	if (!ci)
		return;

	auto *entries = ci->GetExt<TopicHistoryList>(TOPICHISTORY_LIST_EXT);
	if (!entries)
		return;

	auto it = std::find((*entries)->begin(), (*entries)->end(), this);
	if (it != (*entries)->end())
		(*entries)->erase(it);
}

struct TopicHistoryType final
	: Serialize::Type
{
	TopicHistoryType()
		: Serialize::Type(TOPICHISTORY_TYPE)
	{
	}

	void Serialize(Serializable *obj, Serialize::Data &data) const override
	{
		const auto *entry = static_cast<const TopicHistoryEntry *>(obj);
		data.Store("chan", entry->chan);
		data.Store("topic", entry->topic);
		data.Store("setter", entry->setter);
		data.Store("when", entry->when);
	}

	Serializable *Unserialize(Serializable *obj, Serialize::Data &data) const override
	{
		auto *ci = ChannelInfo::Find(data.Load("chan"));
		if (!ci)
			return nullptr;

		const auto topic = data.Load("topic");
		const auto setter = data.Load("setter");
		const auto when = data.Load<time_t>("when");

		if (obj)
		{
			auto *entry = warden_dynamic_static_cast<TopicHistoryEntry *>(obj);
			entry->chan = ci->name;
			entry->topic = topic;
			entry->setter = setter;
			entry->when = when;
			return entry;
		}

		// Keep the list newest first whatever order the database hands
		// the entries back in.
		auto *entry = new TopicHistoryEntry(ci, topic, setter, when);
		auto *entries = ci->Require<TopicHistoryList>(TOPICHISTORY_LIST_EXT);
		auto pos = std::find_if((*entries)->begin(), (*entries)->end(), [when](const auto *e) { return e->when < when; });
		(*entries)->insert(pos, entry);
		return entry;
	}
};

static unsigned maxhistory = 3;

// Starts the list with the current topic, as when the option is turned on.
static void AddCurrentTopic(ChannelInfo *ci)
{
	auto *entries = ci->Require<TopicHistoryList>(TOPICHISTORY_LIST_EXT);
	if ((*entries)->empty())
		(*entries)->push_back(new TopicHistoryEntry(ci, ci->last_topic, ci->last_topic_setter, ci->last_topic_time));
}

class CommandCSTopicHistory final
	: public Command
{
	static void DoList(CommandSource &source, ChannelInfo *ci)
	{
		auto *entries = ci->Require<TopicHistoryList>(TOPICHISTORY_LIST_EXT);

		// Entry 0 is the current topic, so it is not listed.
		if ((*entries)->size() <= 1)
		{
			source.Reply(_("Topic history list for \002%s\002 is empty."), ci->name.c_str());
			return;
		}

		source.Reply(_("Topic history list for \002%s\002:"), ci->name.c_str());

		ListFormatter list(source.GetAccount());
		list.AddColumn(_("Number")).AddColumn(_("Set")).AddColumn(_("By")).AddColumn(_("Topic"));
		list.SetFlexible(_("{number}: {topic} -- set by {by} at {set}"));
		for (size_t i = 1; i < (*entries)->size(); ++i)
		{
			const auto *entry = (*entries)->at(i);

			ListFormatter::ListEntry le;
			le["Number"] = Warden::ToString(i);
			le["Set"] = Warden::strftime(entry->when, source.GetAccount(), true);
			le["By"] = entry->setter;
			le["Topic"] = entry->topic;
			list.AddEntry(le);
		}

		list.SendTo(source);
		source.Reply(_("End of topic history list."));
	}

	void DoClear(CommandSource &source, ChannelInfo *ci)
	{
		// Dropping the list deletes its entries; start again from the
		// current topic.
		ci->Shrink<TopicHistoryList>(TOPICHISTORY_LIST_EXT);
		AddCurrentTopic(ci);

		Log(source.AccessFor(ci).HasPriv("TOPIC") ? LOG_COMMAND : LOG_OVERRIDE, source, this, ci) << "to remove all historical topics";
		source.Reply(_("Topic history for \002%s\002 has been cleared."), ci->name.c_str());
	}

	void DoSet(CommandSource &source, ChannelInfo *ci, const Warden::string &entrynum)
	{
		auto *entries = ci->Require<TopicHistoryList>(TOPICHISTORY_LIST_EXT);
		if ((*entries)->size() <= 1)
		{
			source.Reply(_("Topic history list for \002%s\002 is empty."), ci->name.c_str());
			return;
		}

		const auto i = entrynum.is_pos_number_only() ? Warden::Convert<size_t>(entrynum, 0) : 0;
		if (i < 1 || i >= (*entries)->size())
		{
			source.Reply(_("Topic history entry \002%s\002 not found for \002%s\002."), entrynum.c_str(), ci->name.c_str());
			return;
		}

		const auto topic = (*entries)->at(i)->topic;
		if (ci->c->topic == topic)
		{
			source.Reply(_("History entry \002%zu\002 is already the topic of \002%s\002."), i, ci->name.c_str());
			return;
		}

		// TOPICLOCK would put the old topic straight back.
		const auto topiclock = ci->HasExt("TOPICLOCK");
		ci->Shrink<bool>("TOPICLOCK");
		ci->c->ChangeTopic(source.GetNick(), topic, Warden::CurTime);
		if (topiclock)
			ci->Extend<bool>("TOPICLOCK");

		Log(source.AccessFor(ci).HasPriv("TOPIC") ? LOG_COMMAND : LOG_OVERRIDE, source, this, ci) << "to set a historical topic: " << topic;
		source.Reply(_("Topic of \002%s\002 set to history entry \002%zu\002."), ci->name.c_str(), i);
	}

public:
	CommandCSTopicHistory(Module *creator)
		: Command(creator, "chanserv/topichistory", 2, 3)
	{
		this->SetDesc(_("Maintain a channel's topic history"));
		this->SetSyntax(_("\037channel\037 LIST"));
		this->SetSyntax(_("\037channel\037 CLEAR"));
		this->SetSyntax(_("\037channel\037 SET \037entry-num\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		const auto &subcmd = params[1];

		auto *ci = ChannelInfo::Find(params[0]);
		if (!ci)
			source.Reply(CHAN_X_NOT_REGISTERED, params[0].c_str());
		else if (!source.AccessFor(ci).HasPriv("TOPIC") && !source.HasCommand("chanserv/topic"))
			source.Reply(ACCESS_DENIED);
		else if (!ci->HasExt("TOPICHISTORY"))
			source.Reply(_("Topic history is not enabled for \002%s\002."), ci->name.c_str());
		else if (subcmd.equals_ci("LIST"))
			DoList(source, ci);
		else if (Warden::ReadOnly)
			source.Reply(READ_ONLY_MODE);
		else if (subcmd.equals_ci("CLEAR"))
			this->DoClear(source, ci);
		else if (!subcmd.equals_ci("SET") || params.size() != 3)
			this->OnSyntaxError(source, "");
		else if (!ci->c)
			source.Reply(CHAN_X_NOT_IN_USE, ci->name.c_str());
		else
			this->DoSet(source, ci, params[2]);
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
				"Shows and restores the earlier topics of a channel that has "
				"\002TOPICHISTORY\002 turned on (see \002%s\002). Up to %u "
				"earlier topics are kept."
				"\n\n"
				"\002LIST\002 shows them, numbered from the most recent. "
				"\002SET\002 makes one of them the topic again, even if "
				"\002TOPICLOCK\002 is on. \002CLEAR\002 forgets them all."
				"\n\n"
				"This needs the \002TOPIC\002 privilege on the channel."
			),
			source.service->GetQueryCommand("generic/help", "SET TOPICHISTORY").c_str(),
			maxhistory);
		return true;
	}
};

class CommandCSSetTopicHistory final
	: public Command
{
public:
	CommandCSSetTopicHistory(Module *creator, const Warden::string &cname = "chanserv/set/topichistory")
		: Command(creator, cname, 2, 2)
	{
		this->SetDesc(_("Keep a history of earlier topics"));
		this->SetSyntax(_("\037channel\037 {ON | OFF}"));
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

		if (params[1].equals_ci("ON"))
		{
			Log(source.AccessFor(ci).HasPriv("SET") ? LOG_COMMAND : LOG_OVERRIDE, source, this, ci) << "to enable topichistory";
			ci->Extend<bool>("TOPICHISTORY");
			AddCurrentTopic(ci);
			source.Reply(_("Topic history for \002%s\002 is now \002on\002."), ci->name.c_str());
		}
		else if (params[1].equals_ci("OFF"))
		{
			Log(source.AccessFor(ci).HasPriv("SET") ? LOG_COMMAND : LOG_OVERRIDE, source, this, ci) << "to disable topichistory";
			ci->Shrink<bool>("TOPICHISTORY");
			ci->Shrink<TopicHistoryList>(TOPICHISTORY_LIST_EXT);
			source.Reply(_("Topic history for \002%s\002 is now \002off\002."), ci->name.c_str());
		}
		else
			this->OnSyntaxError(source, "TOPICHISTORY");
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
				"Turns the channel's topic history on or off. While it is on, "
				"the last %u topics are kept and can be listed and restored "
				"with \002%s\002. Turning it off forgets them."
			),
			maxhistory,
			source.service->GetQueryCommand("generic/help", "TOPICHISTORY").c_str());
		return true;
	}
};

class CSTopicHistory final
	: public Module
{
	SerializableExtensibleItem<bool> topichistory;
	ExtensibleItem<TopicHistoryList> topichistorylist;
	TopicHistoryType topichistory_type;
	CommandCSTopicHistory commandcstopichistory;
	CommandCSSetTopicHistory commandcssettopichistory;

public:
	CSTopicHistory(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, VENDOR)
		, topichistory(this, "TOPICHISTORY")
		, topichistorylist(this, TOPICHISTORY_LIST_EXT)
		, commandcstopichistory(this)
		, commandcssettopichistory(this)
	{
	}

	void OnReload(Configuration::Conf &conf) override
	{
		// Entry 0 is the current topic; maxhistory counts the earlier ones.
		maxhistory = std::clamp(conf.GetModule(this).Get<unsigned>("maxhistory", "3"), 1u, 20u);
	}

	void OnTopicUpdated(User *source, Channel *c, const Warden::string &user, const Warden::string &topic) override
	{
		// The burst replays topics we already know.
		if (Me && !Me->IsSynced())
			return;
		if (!c->ci || !c->ci->HasExt("TOPICHISTORY"))
			return;

		auto *entries = c->ci->Require<TopicHistoryList>(TOPICHISTORY_LIST_EXT);

		// A topic that is already in the list moves to the front.
		for (auto *entry : *(*entries))
		{
			if (entry->topic == topic)
			{
				delete entry;
				break;
			}
		}

		while ((*entries)->size() >= maxhistory + 1)
			delete (*entries)->back();

		auto *u = source ? source : User::Find(user);
		const auto ts = c->ci->last_topic_time ? c->ci->last_topic_time : Warden::CurTime;
		(*entries)->insert((*entries)->begin(), new TopicHistoryEntry(c->ci, topic, u ? u->nick : (user.empty() ? "unknown" : user), ts));
	}

	void OnChanInfo(CommandSource &source, ChannelInfo *ci, InfoFormatter &info, bool show_hidden) override
	{
		if (show_hidden && ci->HasExt("TOPICHISTORY"))
			info.AddOption(_("Topic history"));
	}
};

MODULE_INIT(CSTopicHistory)
