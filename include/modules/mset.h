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

// Shared code for NickServ and ChanServ MSET (anope/anope#432): run an
// existing SASET/SET option command once for every account or channel,
// swallowing the per-target replies and log lines and reporting a summary.

#pragma once

namespace MSet
{
	// Collects the replies of one run, grouped with the target's name masked
	// out so "Private option is now on for X." is counted once.
	class Sink final
		: public CommandReply
	{
	public:
		Warden::string target;
		std::map<Warden::string, size_t> replies;
		// Unmasked replies, kept only while probing the first target.
		bool probing = false;
		std::set<Warden::string> raw;

		void SendMessage(BotInfo *, const Warden::string &msg) override
		{
			if (probing)
				raw.insert(msg);
			auto line = msg;
			if (!target.empty())
				line = line.replace_all_ci(target, "*");
			replies[line]++;
		}
	};

	// Set while a run is in progress, so the owning module can quieten the
	// log lines of each per-target command.
	inline bool running = false;

	// Downgrades a log line written during a run to debug level.
	inline void Quieten(Log *l)
	{
		if (running && (l->type == LOG_ADMIN || l->type == LOG_OVERRIDE || l->type == LOG_COMMAND))
			l->type = LOG_DEBUG_4;
	}

	/** Runs `<prefix> <option> <target> <value>` on the source's service for
	 * every target.
	 * @return false (after replying) if the option can't be used.
	 */
	inline bool Run(CommandSource &source, Command *self, const Warden::string &prefix, const Warden::string &option, const Warden::string &value,
		const std::vector<Warden::string> &targets, const std::set<Warden::string> &refused, const char *noun)
	{
		const auto cmdname = prefix + " " + option.upper();
		auto it = source.service->commands.find(cmdname);
		if (it == source.service->commands.end() || option.find(' ') != Warden::string::npos)
		{
			source.Reply(_("Unknown option \002%s\002. Type \002%s\002 for the options you can use."), option.upper().c_str(), source.service->GetQueryCommand("generic/help", prefix).c_str());
			return false;
		}

		const auto &info = it->second;
		if (refused.count(info.name))
		{
			source.Reply(_("\002%s\002 can't be set for every %s at once."), cmdname.c_str(), noun);
			return false;
		}
		if (!info.permission.empty() && !source.HasCommand(info.permission))
		{
			source.Reply(ACCESS_DENIED);
			return false;
		}

		ServiceReference<Command> cmd("Command", info.name);
		if (!cmd)
		{
			source.Reply(_("Unknown option \002%s\002."), option.upper().c_str());
			return false;
		}

		Sink sink;
		auto runone = [&](const Warden::string &target)
		{
			CommandSource tsource(source.GetNick(), source.GetUser(), source.GetAccount(), &sink, source.service);
			std::vector<Warden::string> params = { target };
			if (!value.empty())
				params.push_back(value);
			sink.target = target;
			running = true;
			cmd->Run(tsource, cmdname, info, params);
			running = false;
		};

		if (targets.empty())
		{
			source.Reply(_("There is nothing to change."));
			return false;
		}

		// Try the first target on its own: a bad value always ends in the
		// command's syntax error, which changes nothing, so stop there instead
		// of failing the same way for every other target.
		sink.probing = true;
		runone(targets[0]);
		sink.probing = false;
		const auto syntaxerror = Warden::Format(source.Translate(MORE_INFO), source.service->GetQueryCommand("generic/help", cmdname).c_str());
		if (sink.raw.count(syntaxerror))
		{
			source.Reply(_("Nothing was changed:"));
			for (const auto &line : sink.raw)
				source.Reply("  " + line);
			return false;
		}

		for (size_t i = 1; i < targets.size(); ++i)
			runone(targets[i]);

		Log(LOG_ADMIN, source, self) << cmdname << (value.empty() ? "" : " " + value) << " on " << targets.size() << " " << noun << "(s)";
		source.Reply(_("Ran \002%s%s\002 on %zu %s(s). Replies (* is each %s):"), cmdname.c_str(), (value.empty() ? "" : " " + value).c_str(), targets.size(), noun, noun);

		// Most common replies first.
		std::vector<std::pair<Warden::string, size_t>> sorted(sink.replies.begin(), sink.replies.end());
		std::sort(sorted.begin(), sorted.end(), [](const auto &a, const auto &b) { return a.second > b.second; });
		size_t shown = 0;
		for (const auto &[line, count] : sorted)
		{
			if (++shown > 5)
			{
				source.Reply(_("  ...and %zu other replies."), sorted.size() - 5);
				break;
			}
			source.Reply("  %zux: %s", count, line.c_str());
		}
		return true;
	}
}
