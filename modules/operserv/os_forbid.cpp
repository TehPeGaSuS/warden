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

#include <unordered_set>

#include "module.h"
#include "modules/chanserv/service.h"
#include "modules/nickserv/service.h"
#include "modules/operserv/forbid.h"

// By default users joining a forbidden channel are only kicked, so the channel
// empties and goes away. With chanaction = "hold" the channel is also blocked
// for chanserv:inhabit with a Q-line, or held by ChanServ where the IRCd can't
// Q-line channels. Holding creates an entry for every channel name tried, so a
// user can flood the Q-line list (anope/anope#387).
static void HoldForbiddenChannel(Channel *c, const OperServ::ForbidData *d)
{
	if (!Config->GetModule("os_forbid").Get<const Warden::string>("chanaction", "kick").equals_ci("hold"))
	{
		// Tell ChanServ not to hold the channel once the kick empties it.
		c->Extend<bool>("FORBID_NOHOLD");
		return;
	}

	auto *OperServ = Config->GetClient("OperServ");
	if (IRCD->CanSQLineChannel && OperServ)
	{
		time_t inhabit = Config->GetModule("chanserv").Get<time_t>("inhabit", "1m");
		XLine x(c->name, OperServ->nick, Warden::CurTime + inhabit, d->reason);
		IRCD->SendSQLine(NULL, &x);
	}
	else if (ChanServ::service)
	{
		ChanServ::service->Hold(c);
	}
}

namespace
{
	Warden::string TypeToString(OperServ::ForbidType ft)
	{
		switch (ft)
		{
			case OperServ::FT_NICK:
				return "NICK";
			case OperServ::FT_CHAN:
				return "CHAN";
			case OperServ::FT_EMAIL:
				return "EMAIL";
			case OperServ::FT_REGISTER:
				return "REGISTER";
			case OperServ::FT_PASSWORD:
				return "PASSWORD";
			default:
				return "UNKNOWN"; // Should never happen.
		}
	}

	OperServ::ForbidType StringToType(const Warden::string &ft)
	{
		if (ft.equals_ci("NICK") || ft.equals_ci("1"))
			return OperServ::FT_NICK;
		if (ft.equals_ci("CHAN") || ft.equals_ci("2"))
			return OperServ::FT_CHAN;
		if (ft.equals_ci("EMAIL") || ft.equals_ci("3"))
			return OperServ::FT_EMAIL;
		if (ft.equals_ci("REGISTER") || ft.equals_ci("4"))
			return OperServ::FT_REGISTER;
		if (ft.equals_ci("PASSWORD"))
			return OperServ::FT_PASSWORD;

		return OperServ::FT_SIZE; // Should never happen.
	}
}

struct ForbidDataImpl final
	: OperServ::ForbidData
	, Serializable
{
	ForbidDataImpl()
		: Serializable(OPERSERV_FORBID_DATA_TYPE)
	{
	}
};

struct ForbidDataFile final
	: OperServ::ForbidData
{
	ForbidDataFile(OperServ::ForbidType t, const Warden::string &c, const Warden::string &m, const Warden::string &r)
	{
		created = Warden::CurTime;
		creator = c;
		immutable = true;
		mask = m;
		reason = r;
		type = t;
	}
};

struct ForbidDataTypeImpl final
	: Serialize::Type
{
	ForbidDataTypeImpl()
		: Serialize::Type(OPERSERV_FORBID_DATA_TYPE)
	{
	}

	void Serialize(Serializable *obj, Serialize::Data &data) const override;
	Serializable *Unserialize(Serializable *obj, Serialize::Data &data) const override;
};

void ForbidDataTypeImpl::Serialize(Serializable *obj, Serialize::Data &data) const
{
	const auto *fb = static_cast<const ForbidDataImpl *>(obj);
	data.Store("mask", fb->mask);
	data.Store("creator", fb->creator);
	data.Store("reason", fb->reason);
	data.Store("created", fb->created);
	data.Store("expires", fb->expires);
	data.Store("type", TypeToString(fb->type));
}

Serializable *ForbidDataTypeImpl::Unserialize(Serializable *obj, Serialize::Data &data) const
{
	if (!OperServ::forbid_service)
		return NULL;

	ForbidDataImpl *fb;
	if (obj)
		fb = warden_dynamic_static_cast<ForbidDataImpl *>(obj);
	else
		fb = new ForbidDataImpl();

	fb->mask = data.Load("mask");
	fb->creator = data.Load("creator");
	fb->reason = data.Load("reason");
	fb->created = data.Load<time_t>("created");
	fb->expires = data.Load<time_t>("expires");
	fb->type = StringToType(data.Load("type"));

	if (fb->type == OperServ::FT_SIZE)
		return NULL;

	if (!obj)
		OperServ::forbid_service->AddForbid(fb);
	return fb;
}

class MyForbidService final
	: public OperServ::ForbidService
{
	Serialize::Checker<std::vector<OperServ::ForbidData *>[OperServ::FT_SIZE - 1]> forbid_data;

	inline std::vector<OperServ::ForbidData *>& forbids(unsigned t) { return (*this->forbid_data)[t - 1]; }

	void Expire(OperServ::ForbidData *fd, unsigned ft, size_t idx)
	{
		Log(LOG_NORMAL, "expire/forbid", Config->GetClient("OperServ")) << "Expiring forbid for " << fd->mask << " type " << TypeToString(static_cast<OperServ::ForbidType>(ft));
		this->forbids(ft).erase(this->forbids(ft).begin() + idx);
		delete fd;
	}

public:
	MyForbidService(Module *m)
		: OperServ::ForbidService(m)
		, forbid_data(OPERSERV_FORBID_DATA_TYPE)
	{
	}

	~MyForbidService() override
	{
		for (const auto *forbid : GetForbids())
			delete forbid;
	}

	void AddForbid(OperServ::ForbidData *d) override
	{
		this->forbids(d->type).push_back(d);
	}

	void RemoveForbid(OperServ::ForbidData *d) override
	{
		auto it = std::find(this->forbids(d->type).begin(), this->forbids(d->type).end(), d);
		if (it != this->forbids(d->type).end())
			this->forbids(d->type).erase(it);
		delete d;
	}

	OperServ::ForbidData *CreateForbid() override
	{
		return new ForbidDataImpl();
	}

	OperServ::ForbidData *FindForbid(const Warden::string &mask, OperServ::ForbidType ftype) override
	{
		for (unsigned i = this->forbids(ftype).size(); i > 0; --i)
		{
			auto *d = this->forbids(ftype)[i - 1];

			if (!Warden::NoExpire && d->expires && Warden::CurTime >= d->expires)
			{
				Expire(d, ftype, i - 1);
				continue;
			}

			if (Warden::Match(mask, d->mask, false, true))
				return d;
		}
		return NULL;
	}

	OperServ::ForbidData *FindForbidExact(const Warden::string &mask, OperServ::ForbidType ftype) override
	{
		for (unsigned i = this->forbids(ftype).size(); i > 0; --i)
		{
			auto *d = this->forbids(ftype)[i - 1];

			if (!Warden::NoExpire && d->expires && Warden::CurTime >= d->expires)
			{
				Expire(d, ftype, i - 1);
				continue;
			}

			if (d->mask.equals_ci(mask))
				return d;
		}
		return NULL;
	}

	std::vector<OperServ::ForbidData *> GetForbids() override
	{
		std::vector<OperServ::ForbidData *> f;
		for (unsigned j = OperServ::FT_NICK; j < OperServ::FT_SIZE; ++j)
			for (unsigned i = this->forbids(j).size(); i > 0; --i)
			{
				auto *d = this->forbids(j).at(i - 1);

				if (d->expires && !Warden::NoExpire && Warden::CurTime >= d->expires)
					Expire(d, j, i - 1);
				else
					f.push_back(d);
			}

		return f;
	}
};

class CommandOSForbid final
	: public Command
{
public:
	CommandOSForbid(Module *creator)
		: Command(creator, "operserv/forbid", 1, 5)
	{
		this->SetDesc(_("Forbid usage of nicknames, channels, and emails"));
		this->SetSyntax(_("ADD {CHAN|EMAIL|NICK|PASSWORD|REGISTER} [+\037expiry\037] \037entry\037 \037reason\037"));
		this->SetSyntax(_("DEL {CHAN|EMAIL|NICK|PASSWORD|REGISTER} \037entry\037"));
		this->SetSyntax(_("LIST {CHAN|EMAIL|NICK|PASSWORD|REGISTER} [\037from\037-\037to\037]"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params_) override
	{
		if (!OperServ::forbid_service)
		{
			source.Reply(TRY_AGAIN_LATER, source.command.nobreak().c_str());
			return;
		}

		/* "LIST [type] [from-to]" allows the type to be omitted (list all
		 * types), which means the range can land right after LIST instead
		 * of after the type -- eg. "FORBID LIST 15-30". Peel a trailing
		 * range off by shape before doing the normal positional parsing
		 * below, same as os_list_paged does, and remember it separately so
		 * it doesn't get mistaken for the type.
		 */
		std::vector<Warden::string> params = params_;
		Warden::string rangearg;
		if (params.size() > 1 && params[0].equals_ci("LIST") && params.back().find('-') != Warden::string::npos)
		{
			Warden::string n1, n2;
			sepstream(params.back(), '-').GetToken(n1, 0);
			sepstream(params.back(), '-').GetToken(n2, 1);
			if (Warden::TryConvert<unsigned>(n1).has_value() && Warden::TryConvert<unsigned>(n2).has_value())
			{
				rangearg = params.back();
				params.pop_back();
			}
		}

		const Warden::string &command = params[0];
		const Warden::string &subcommand = params.size() > 1 ? params[1] : "";

		auto ftype = StringToType(subcommand);
		if (command.equals_ci("ADD") && params.size() > 3 && ftype != OperServ::FT_SIZE)
		{
			const Warden::string &expiry = params[2][0] == '+' ? params[2] : "";
			const Warden::string &entry = !expiry.empty() ? params[3] : params[2];
			Warden::string reason;
			if (expiry.empty())
				reason = params[3] + " ";
			if (params.size() > 4)
				reason += params[4];
			reason.trim();

			if (entry.replace_all_cs("?*", "").empty())
			{
				source.Reply(_("The mask must contain at least one non wildcard character."));
				return;
			}

			time_t expiryt = 0;

			if (!expiry.empty())
			{
				expiryt = Warden::DoTime(expiry);
				if (expiryt < 0)
				{
					source.Reply(BAD_EXPIRY_TIME);
					return;
				}
				else if (expiryt)
					expiryt += Warden::CurTime;
			}

			NickAlias *target = NickAlias::Find(entry);
			if (target != NULL && Config->GetModule("nickserv").Get<bool>("secureadmins", "yes") && target->nc->IsServicesOper())
			{
				source.Reply(ACCESS_DENIED);
				return;
			}

			auto *d = OperServ::forbid_service->FindForbidExact(entry, ftype);
			bool created = false;
			if (d == NULL)
			{
				d = new ForbidDataImpl();
				created = true;
			}

			d->mask = entry;
			d->creator = source.GetNick();
			d->reason = reason;
			d->created = Warden::CurTime;
			d->expires = expiryt;
			d->type = ftype;
			if (created)
				OperServ::forbid_service->AddForbid(d);

			if (Warden::ReadOnly)
				source.Reply(READ_ONLY_MODE);

			Log(LOG_ADMIN, source, this) << "to add a forbid on " << entry << " of type " << subcommand;
			source.Reply(_("Added a forbid on %s of type %s to expire on %s."), entry.c_str(), subcommand.lower().c_str(), d->expires ? Warden::strftime(d->expires, source.GetAccount()).c_str() : "never");

			/* apply forbid */
			switch (ftype)
			{
				case OperServ::FT_NICK:
				{
					int na_matches = 0;

					for (const auto &[_, user] : UserListByNick)
						module->OnUserNickChange(user, "");

					for (auto it = NickAliasList->begin(), it_end = NickAliasList->end(); it != it_end;)
					{
						NickAlias *na = it->second;
						++it;

						d = OperServ::forbid_service->FindForbid(na->nick, OperServ::FT_NICK);
						if (d == NULL)
							continue;

						++na_matches;

						delete na;
					}

					source.Reply(na_matches, N_("\002%d\002 nickname dropped.", "\002%d\002 nicknames dropped."), na_matches);
					break;
				}
				case OperServ::FT_CHAN:
				{
					int chan_matches = 0, ci_matches = 0;

					for (auto it = ChannelList.begin(), it_end = ChannelList.end(); it != it_end;)
					{
						Channel *c = it->second;
						++it;

						d = OperServ::forbid_service->FindForbid(c->name, OperServ::FT_CHAN);
						if (d == NULL)
							continue;

						HoldForbiddenChannel(c, d);

						++chan_matches;

						for (auto cit = c->users.begin(), cit_end = c->users.end(); cit != cit_end;)
						{
							User *u = cit->first;
							++cit;

							if (u->server == Me || u->HasMode("OPER"))
								continue;

							reason = Warden::Format(Language::Translate(u, _("This channel has been forbidden: %s")), d->reason.c_str());

							c->Kick(source.service, u, reason);
						}
					}

					for (auto it = RegisteredChannelList->begin(); it != RegisteredChannelList->end();)
					{
						ChannelInfo *ci = it->second;
						++it;

						d = OperServ::forbid_service->FindForbid(ci->name, OperServ::FT_CHAN);
						if (d == NULL)
							continue;

						++ci_matches;

						delete ci;
					}

					source.Reply(_("\002%d\002 channel(s) cleared, and \002%d\002 channel(s) dropped."), chan_matches, ci_matches);

					break;
				}
				default:
					break;
			}

		}
		else if (command.equals_ci("DEL") && params.size() > 2 && ftype != OperServ::FT_SIZE)
		{
			const Warden::string &entry = params[2];

			auto *d = OperServ::forbid_service->FindForbidExact(entry, ftype);
			if (d != NULL)
			{
				if (Warden::ReadOnly)
					source.Reply(READ_ONLY_MODE);
				else if (d->immutable)
					source.Reply(_("Forbid on %s can not be removed as it is from a file."), entry.c_str());
				else
				{
					Log(LOG_ADMIN, source, this) << "to remove forbid on " << d->mask << " of type " << subcommand;
					source.Reply(_("%s deleted from the %s forbid list."), d->mask.c_str(), subcommand.c_str());
					OperServ::forbid_service->RemoveForbid(d);
				}
			}
			else
				source.Reply(_("Forbid on %s was not found."), entry.c_str());
		}
		else if (command.equals_ci("LIST"))
		{
			const auto &forbids = OperServ::forbid_service->GetForbids();
			if (forbids.empty())
				source.Reply(_("Forbid list is empty."));
			else
			{
				unsigned from = 0, to = 0;
				if (!rangearg.empty())
				{
					Warden::string n1, n2;
					sepstream(rangearg, '-').GetToken(n1, 0);
					sepstream(rangearg, '-').GetToken(n2, 1);

					auto num1 = Warden::TryConvert<unsigned>(n1);
					auto num2 = Warden::TryConvert<unsigned>(n2);
					if (!num1.has_value() || !num2.has_value())
					{
						source.Reply(_("Incorrect range specified. The correct syntax is \037from\037-\037to\037."));
						return;
					}

					from = num1.value();
					to = num2.value();
				}

				ListFormatter list(source.GetAccount());
				list.AddColumn(_("Mask")).AddColumn(_("Type")).AddColumn(_("Creator")).AddColumn(_("Expires")).AddColumn(_("Reason"));
				list.SetFlexible([](ListFormatter::ListEntry &row)
				{
					return row["Reason"].empty()
						? _("\002{mask}\002 on {type} -- created by {creator}; expires in {expires}")
						: _("\002{mask}\002 on {type} -- created by {creator}; expires in {expires} ({reason})");
				});

				/* An explicit range is the oper's own paging mechanism, so it isn't
				 * additionally capped by listmax -- only the default (unbounded)
				 * listing is.
				 */
				const auto listmax = Config->GetModule(this->owner).Get<unsigned>("listmax", "50");
				const auto cap = (from || to) ? 0 : listmax;

				size_t matched = 0, shown = 0, shown_from = 0, shown_to = 0;
				for (auto *forbid : forbids)
				{
					if (ftype != OperServ::FT_SIZE && ftype != forbid->type)
						continue;

					auto stype = TypeToString(forbid->type);
					if (stype == OperServ::FT_SIZE)
						continue;

					++matched;

					if (from || to)
					{
						if (matched < from || matched > to)
							continue;
					}

					if (cap && shown >= cap)
						continue;

					ListFormatter::ListEntry entry;
					entry["Mask"] = forbid->mask;
					entry["Type"] = stype;
					entry["Creator"] = forbid->creator;
					entry["Expires"] = forbid->expires ? Warden::strftime(forbid->expires, NULL, true).c_str() : TIME_NEVER;
					entry["Reason"] = forbid->reason;
					list.AddEntry(entry);

					if (!shown)
						shown_from = matched;
					shown_to = matched;
					++shown;
				}

				if (!matched)
				{
					source.Reply(_("There are no forbids of type %s."), subcommand.upper().c_str());
				}
				else
				{
					source.Reply(_("Forbid list:"));
					list.SendTo(source);

					if (shown >= matched)
						source.Reply(_("End of forbid list."));
					else
						source.Reply(_("End of forbid list - %zu/%zu entries shown (%zu-%zu)."), shown, matched, shown_from, shown_to);
				}
			}
		}
		else
			this->OnSyntaxError(source, command);
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Forbid allows you to forbid usage of certain nicknames, channels, "
			"and email addresses. Wildcards are accepted for all entries."
			"\n\n"
			"When listing forbids, an optional \037from\037-\037to\037 range "
			"(eg. \002101-210\002) may be given to page through large forbid "
			"lists. Without a range, the default (unranged) list is capped "
			"by the listmax configuration option."
		));

		const Warden::string &regexengine = Config->GetBlock("options").Get<const Warden::string>("regexengine");
		if (!regexengine.empty())
		{
			source.Reply(" ");
			source.Reply(_(
					"Regex matches are also supported using the %s engine. "
					"Enclose your pattern in // if this is desired."
				),
				regexengine.c_str());
		}

		return true;
	}
};

class OSForbid final
	: public Module
{
private:
	MyForbidService forbidService;
	ForbidDataTypeImpl forbiddata_type;
	CommandOSForbid commandosforbid;
	std::vector<OperServ::ForbidData *> fileforbids;
	ExtensibleItem<bool> nohold;

public:
	OSForbid(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, VENDOR)
		, forbidService(this)
		, commandosforbid(this)
		, nohold(this, "FORBID_NOHOLD")
	{
	}

	void OnReload(Configuration::Conf &conf) override
	{
		for (auto* fileforbid : fileforbids)
			forbidService.RemoveForbid(fileforbid);
		fileforbids.clear();

		const auto &modconf = conf.GetModule(this);
		for (const auto &[_,  fileblock] : modconf.GetBlocks("file"))
		{
			const auto reasonstr = fileblock.Get<const Warden::string>("reason");

			const auto typestr = fileblock.Get<const Warden::string>("type");
			auto type = StringToType(typestr);
			if (type == OperServ::FT_SIZE)
			{
				Log(this) << "Unknown forbid file type: " << typestr << ", ignoring.";
				continue;
			}

			const auto filestr = Warden::ExpandConfig(fileblock.Get<const Warden::string>("file"));
			std::ifstream file(filestr.str());
			if (!file.is_open())
			{
				Log(this) << "Unable to read " << filestr << ", ignoring.";
				continue;
			}
			// Masks of this type that already exist, so each line's duplicate
			// check is O(1). Calling FindForbidExact per line scanned the whole
			// list every time, making a reload O(n^2): ~12-15 s for a 10k-line
			// file, with services frozen meanwhile (anope/anope#625).
			//
			// The key is upper(): FindForbidExact matches with equals_ci, which
			// compares through the casemap's upper table, and upper() uses the
			// same table. So two masks get the same key exactly when
			// FindForbidExact would call them equal, under any casemap.
			// (Hashing with Warden::hash_ci would not: it hashes lower(), which
			// can disagree with equals_ci for some casemaps.)
			// GetForbids() also expires stale forbids first, like
			// FindForbidExact did, so expired entries don't count as duplicates.
			std::unordered_set<std::string> existing;
			for (const auto *forbid : forbidService.GetForbids())
			{
				if (forbid->type == type)
					existing.insert(forbid->mask.upper().str());
			}

			for (Warden::string forbidstr; std::getline(file, forbidstr.str()); )
			{
				forbidstr = forbidstr.trim();
				if (forbidstr.empty())
					continue;

				if (!existing.insert(forbidstr.upper().str()).second)
				{
					Log(this) << "Forbid on " << forbidstr << " already exists, ignoring.";
					continue;
				}

				auto *forbid = new ForbidDataFile(type, filestr, forbidstr, reasonstr);
				forbidService.AddForbid(forbid);
				fileforbids.push_back(forbid);
				Log(LOG_DEBUG) << "Added a file forbid on " << forbidstr << ": " << reasonstr;
			}
		}
	}

	void OnUserConnect(User *u, bool &exempt) override
	{
		if (u->Quitting() || exempt)
			return;

		this->OnUserNickChange(u, "");
	}

	void OnUserNickChange(User *u, const Warden::string &) override
	{
		if (u->HasMode("OPER"))
			return;

		auto *d = this->forbidService.FindForbid(u->nick, OperServ::FT_NICK);
		if (d != NULL)
		{
			BotInfo *bi = Config->GetClient("NickServ");
			if (!bi)
				bi = Config->GetClient("OperServ");
			if (bi)
				u->SendMessage(bi, _("This nickname has been forbidden: %s"), d->reason.c_str());
			if (NickServ::service)
				NickServ::service->Collide(u, NULL);
		}
	}

	EventReturn OnCheckKick(User *u, Channel *c, Warden::string &mask, Warden::string &reason) override
	{
		BotInfo *OperServ = Config->GetClient("OperServ");
		if (u->HasMode("OPER") || !OperServ)
			return EVENT_CONTINUE;

		auto *d = this->forbidService.FindForbid(c->name, OperServ::FT_CHAN);
		if (d != NULL)
		{
			HoldForbiddenChannel(c, d);

			reason = Warden::Format(Language::Translate(u, _("This channel has been forbidden: %s")), d->reason.c_str());

			return EVENT_STOP;
		}

		return EVENT_CONTINUE;
	}

	EventReturn OnPasswordValidate(CommandSource &source, NickCore *nc, const Warden::string &pass) override
	{
		const auto* forbid = this->forbidService.FindForbid(pass, OperServ::FT_PASSWORD);
		if (forbid != nullptr)
		{
			if (source.IsOper())
				source.Reply(_("The password you specified is forbidden by %s: %s"), forbid->creator.c_str(), forbid->reason.c_str());
			else
				source.Reply(_("The password you specified is forbidden."));
			return EVENT_STOP;
		}
		return EVENT_CONTINUE;
	}

	EventReturn OnPreCommand(CommandSource &source, Command *command, std::vector<Warden::string> &params) override
	{
		if (command->name == "nickserv/info" && !params.empty() && params[0][0] != '=')
		{
			auto *d = this->forbidService.FindForbid(params[0], OperServ::FT_NICK);
			if (d != NULL)
			{
				if (source.IsOper())
					source.Reply(_("Nick \002%s\002 is forbidden by %s: %s"), params[0].c_str(), d->creator.c_str(), d->reason.c_str());
				else
					source.Reply(_("Nick \002%s\002 is forbidden."), params[0].c_str());
				return EVENT_STOP;
			}
		}
		else if (command->name == "chanserv/info" && params.size() > 0)
		{
			auto *d = this->forbidService.FindForbid(params[0], OperServ::FT_CHAN);
			if (d != NULL)
			{
				if (source.IsOper())
					source.Reply(_("Channel \002%s\002 is forbidden by %s: %s"), params[0].c_str(), d->creator.c_str(), d->reason.c_str());
				else
					source.Reply(_("Channel \002%s\002 is forbidden."), params[0].c_str());
				return EVENT_STOP;
			}
		}
		else if (source.IsOper())
			return EVENT_CONTINUE;
		else if (command->name == "nickserv/register" && params.size() > 1)
		{
			auto *d = this->forbidService.FindForbid(source.GetNick(), OperServ::FT_REGISTER);
			if (d != NULL)
			{
				source.Reply(NICK_CANNOT_BE_REGISTERED, source.GetNick().c_str());
				return EVENT_STOP;
			}

			d = this->forbidService.FindForbid(params[1], OperServ::FT_EMAIL);
			if (d != NULL)
			{
				source.Reply(_("Your email address is not allowed, choose a different one."));
				return EVENT_STOP;
			}
		}
		else if (command->name == "nickserv/set/email" && params.size() > 0)
		{
			auto *d = this->forbidService.FindForbid(params[0], OperServ::FT_EMAIL);
			if (d != NULL)
			{
				source.Reply(_("Your email address is not allowed, choose a different one."));
				return EVENT_STOP;
			}
		}
		else if (command->name == "chanserv/register" && !params.empty())
		{
			auto *d = this->forbidService.FindForbid(params[0], OperServ::FT_REGISTER);
			if (d != NULL)
			{
				source.Reply(CHAN_X_INVALID, params[0].c_str());
				return EVENT_STOP;
			}
		}

		return EVENT_CONTINUE;
	}
};

MODULE_INIT(OSForbid)
