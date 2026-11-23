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
#include "modules/chanserv/mode.h"
#include "modules/encryption.h"
#include "modules/httpd.h"
#include "modules/nickserv/cert.h"
#include "modules/nickserv/sasl.h"

typedef std::map<char, unsigned> ListLimits;

struct SASLUser final
{
	Warden::string uid;
	Warden::string acc;
	time_t created;
};

namespace
{
	/** Whether we should send extbans using their named form. */
	bool named_extbans = false;

	// The SID of a server we are waiting to squit.
	Warden::string rsquit_id;

	// The hostname of a server we are waiting to squit.
	Warden::string rsquit_server;

	// Non-introduced users who have authenticated via SASL.
	std::list<SASLUser> saslusers;

	// A reference to the SHA-2 algorithm provider.
	static ServiceReference<Encryption::Provider> sha256("Encryption::Provider", "sha256");

	// The version of the InspIRCd protocol that we are using.
	size_t spanningtree_proto_ver = 1206;

	bool IsExtBan(const Warden::string &str, bool &inverted, Warden::string &name, Warden::string &value)
	{
		auto startpos = 0;
		if (!str.empty() && str[0] == '!')
			startpos++;

		auto endpos = str.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", startpos);
		if (endpos == Warden::string::npos || str[endpos] != ':' || endpos+1 == str.length())
			return false;

		inverted = !!startpos;
		name = str.substr(startpos, endpos - startpos);
		value = str.substr(endpos + 1);
		return true;
	}

	// Parses a module name in the format "m_foo.so=bar" to {foo, bar}.
	void ParseModule(const Warden::string &module, Warden::string &modname, Warden::string &moddata)
	{
		size_t sep = module.find('=');

		// Extract and clean up the module name.
		modname = module.substr(0, sep);
		if (modname.compare(0, 2, "m_", 2) == 0)
			modname.erase(0, 2);

		if (modname.length() > 3 && modname.compare(modname.length() - 3, 3, ".so", 3) == 0)
			modname.erase(modname.length() - 3);

		// Extract the module link data (if any).
		moddata = (sep == Warden::string::npos) ? "" : module.substr(sep + 1);

		if (Warden::ProtocolDebug)
			Log(LOG_DEBUG) << "Parsed module: name=" << modname << " data=" << moddata;
	}

	void ParseModuleData(const Warden::string &moddata, Warden::map<Warden::string> &modmap)
	{
		sepstream datastream(moddata, '&');
		for (Warden::string datapair; datastream.GetToken(datapair); )
		{
			size_t split = datapair.find('=');
			std::pair<Warden::map<Warden::string>::iterator, bool> res;
			if (split == Warden::string::npos)
				res = modmap.emplace(datapair, "");
			else
				res = modmap.emplace(datapair.substr(0, split), HTTP::URLDecode(datapair.substr(split + 1)));

			if (Warden::ProtocolDebug && res.second)
				Log(LOG_DEBUG) << "Parsed module data: key=" << res.first->first << " value=" << res.first->second;
		}
	}
}

class InspIRCdProto final
	: public IRCDProto
	, public SASL::ProtocolInterface
{
private:
	static Warden::string GetAccountNicks(NickAlias* na)
	{
		if (!na || Config->GetModule("nickserv").Get<bool>("nonicknameownership"))
			return {};

		Warden::string nicks;
		for (const auto &na : *na->nc->aliases)
			nicks += " " + na->nick;
		return nicks.substr(1);
	}

	static void SendChgIdentInternal(const Warden::string &uid, const Warden::string &vident)
	{
		if (!Servers::Capab.count("CHGIDENT"))
		{
			Log() << "Unable to change the vident of " << uid << " as the remote server does not have the chgident module loaded.";
			return;
		}
		Uplink::Send("ENCAP", uid.substr(0, 3), "CHGIDENT", uid, vident);
	}

	static void SendChgHostInternal(const Warden::string &uid, const Warden::string &vhost)
	{
		if (!Servers::Capab.count("CHGHOST"))
		{
			Log() << "Unable to change the vhost of " << uid << " as the remote server does not have the chghost module loaded.";
			return;
		}
		Uplink::Send("ENCAP", uid.substr(0, 3), "CHGHOST", uid, vhost);
	}

	static void SendAddLine(const Warden::string &xtype, const Warden::string &mask, time_t duration, const Warden::string &addedby, const Warden::string &reason)
	{
		Uplink::Send("ADDLINE", xtype, mask, addedby, Warden::CurTime, duration, reason);
	}

	static void SendDelLine(const Warden::string &xtype, const Warden::string &mask)
	{
		Uplink::Send("DELLINE", xtype, mask);
	}

	static void SendAccount(const Warden::string &uid, NickAlias *na)
	{
		Uplink::Send("METADATA", uid, "accountid", na ? Warden::ToString(na->nc->GetId()) : Warden::string());
		Uplink::Send("METADATA", uid, "accountname", na ? na->nc->display : Warden::string());
		Uplink::Send("METADATA", uid, "accountnicks", GetAccountNicks(na));
	}

	static void SendVHostInternal(const Warden::string &uid, const Warden::string &vident, const Warden::string &vhost)
	{
		if (Servers::Capab.count("CLOAK"))
		{
			Warden::string cloak;
			if (!vident.empty())
				cloak.append(vident).push_back('@');
			cloak.append(vhost);

			Uplink::Send("METADATA", uid, "custom-cloak", cloak);
			return;
		}

		if (!vident.empty())
			SendChgIdentInternal(uid, vident);
		SendChgHostInternal(uid, vhost);
	}

public:
	PrimitiveExtensibleItem<ListLimits> maxlist;

	InspIRCdProto(Module *creator)
		: IRCDProto(creator, "InspIRCd 4+")
		, SASL::ProtocolInterface(creator)
		, maxlist(creator, "maxlist")
	{
		CanCertFP = true;
		CanSetVHost = true;
		CanSetVIdent = true;
		CanSQLine = true;
		CanSVSHold = true;
		CanSVSJoin = true;
		CanSVSNick = true;
		CanSZLine = true;
		RequiresID = true;
		DefaultPseudoclientModes = "+oI";
		MaxLine = 0;
		MaxModes = 0;
	}

	void GetLinkAdvice(std::vector<Warden::string> &advice) override
	{
		advice.push_back("You do not have the account, hidechans, services, and spanningtree modules loaded on InspIRCd.");
	}

	size_t GetMaxListFor(Channel *c, ChannelMode *cm) override
	{
		ListLimits *limits = maxlist.Get(c);
		if (limits)
		{
			auto limit = limits->find(cm->GetBaseMode()->mchar);
			if (limit != limits->end())
				return limit->second;
		}

		// Fall back to the config limit if we can't find the mode.
		return IRCDProto::GetMaxListFor(c, cm);
	}


	void SendConnect() override
	{
		Uplink::Send("CAPAB", "START", 1206);
		Uplink::Send("CAPAB", "CAPABILITIES", "CASEMAPPING=" + Config->GetBlock("options").Get<const Warden::string>("casemap", "ascii") + (sha256 ? " CHALLENGE=*" : ""));
		Uplink::Send("CAPAB", "END");
	}

	void SendSASLMechanisms(std::vector<Warden::string> &mechanisms) override
	{
		Warden::string mechlist;
		for (const auto &mechanism : mechanisms)
			mechlist += "," + mechanism;

		Uplink::Send("METADATA", "*", "saslmechlist", mechanisms.empty() ? "" : mechlist.substr(1));
	}

	void SendSVSKill(const MessageSource &source, User *user, const Warden::string &buf) override
	{
		IRCDProto::SendSVSKill(source, user, buf);
		user->KillInternal(source, buf);
	}

	void SendForceNickChange(User *u, const Warden::string &newnick, time_t when) override
	{
		Uplink::Send("SVSNICK", u->GetUID(), newnick, when, u->timestamp);
	}

	void SendGlobalNotice(BotInfo *bi, const Server *dest, const Warden::string &msg) override
	{
		Uplink::Send(bi, "NOTICE", "$" + dest->GetName(), msg);
	}

	void SendGlobalPrivmsg(BotInfo *bi, const Server *dest, const Warden::string &msg) override
	{
		Uplink::Send(bi, "PRIVMSG", "$" + dest->GetName(), msg);
	}

	void SendContextNotice(BotInfo *bi, User *target, Channel *context, const Warden::string &msg,  const Warden::map<Warden::string> &tags) override
	{
		auto newtags = tags;
		newtags["~context"] = context->name;
		IRCD->SendNotice(bi, target->GetUID(), msg, newtags);
	}

	void SendContextPrivmsg(BotInfo *bi, User *target, Channel *context, const Warden::string &msg, const Warden::map<Warden::string> &tags) override
	{
		auto newtags = tags;
		newtags["~context"] = context->name;
		IRCD->SendPrivmsg(bi, target->GetUID(), msg, newtags);
	}

	void SendClearModes(const MessageSource &user, Channel *c, User* u, const Warden::string &mode, bool self) override
	{
		auto *cm = ModeManager::FindChannelModeByName(mode);
		if (!cm || !cm->mchar)
			return;

		Uplink::Send(user, "SVSCMODE", u->GetUID(), c->name, cm->mchar, self);
	}

	void SendQuit(User *u, const Warden::string &buf, const Warden::string &operbuf) override
	{
		if (!operbuf.empty())
			Uplink::Send("METADATA", u->GetUID(), "operquit", operbuf);

		IRCDProto::SendQuit(u, buf, operbuf);
	}

	void SendPing(const Warden::string &servname, const Warden::string &who) override
	{
		Uplink::Send("PING", who);
	}

	void SendPong(const Warden::string &servname, const Warden::string &who) override
	{
		Server *serv = servname.empty() ? NULL : Server::Find(servname);
		if (!serv)
			serv = Me;

		Uplink::Send(serv, "PONG", who);
	}

	void SendAkillDel(const XLine *x) override
	{
		{
			/* InspIRCd may support regex bans
			 * Mask is expected in format: 'n!u@h\sr' and spaces as '\s'
			 * We remove the '//' and replace '#' and any ' ' with '\s'
			 */
			if (x->IsRegex() && Servers::Capab.count("RLINE"))
			{
				Warden::string mask = x->mask;
				if (mask.length() >= 2 && mask[0] == '/' && mask[mask.length() - 1] == '/')
					mask = mask.substr(1, mask.length() - 2);
				size_t h = mask.find('#');
				if (h != Warden::string::npos)
				{
					mask = mask.replace(h, 1, "\\s");
					mask = mask.replace_all_cs(" ", "\\s");
				}
				SendDelLine("R", mask);
				return;
			}
			else if (x->IsRegex() || x->HasNickOrReal())
				return;

			/* ZLine if we can instead */
			if (x->GetUser() == "*")
			{
				cidr addr(x->GetHost());
				if (addr.valid())
				{
					IRCD->SendSZLineDel(x);
					return;
				}
			}

			SendDelLine("G", x->GetUser() + "@" + x->GetHost());
		}
	}

	void SendInvite(const MessageSource &source, const Channel *c, User *u) override
	{
		Uplink::Send(source, "INVITE", u->GetUID(), c->name, c->created);
	}

	void SendTopic(const MessageSource &source, Channel *c) override
	{
		Uplink::Send(c->WhoSends(), "SVSTOPIC", c->name, c->topic_ts, c->topic_setter, c->topic);
	}

	void SendVHostDel(User *u) override
	{
		UserMode *um = ModeManager::FindUserModeByName("CLOAK");

		if (um && !u->HasMode(um->name))
			// Just set +x if we can
			u->SetMode(NULL, um);
		else
			// Try to restore cloaked host
			this->SendChgHostInternal(u->GetUID(), u->chost);
	}

	void SendAkill(User *u, XLine *x) override
	{
		// Calculate the time left before this would expire
		time_t timeleft = x->expires ? x->expires - Warden::CurTime : x->expires;

		/* InspIRCd may support regex bans, if they do we can send this and forget about it
		 * Mask is expected in format: 'n!u@h\sr' and spaces as '\s'
		 * We remove the '//' and replace '#' and any ' ' with '\s'
		 */
		if (x->IsRegex() && Servers::Capab.count("RLINE"))
		{
			Warden::string mask = x->mask;
			if (mask.length() >= 2 && mask[0] == '/' && mask[mask.length() - 1] == '/')
				mask = mask.substr(1, mask.length() - 2);
			size_t h = mask.find('#');
			if (h != Warden::string::npos)
			{
				mask = mask.replace(h, 1, "\\s");
				mask = mask.replace_all_cs(" ", "\\s");
			}
			SendAddLine("R", mask, timeleft, x->by, x->GetReason());
			return;
		}
		else if (x->IsRegex() || x->HasNickOrReal())
		{
			if (!u)
			{
				/* No user (this akill was just added), and contains nick and/or realname. Find users that match and ban them */
				for (const auto &[_, user] : UserListByNick)
					if (x->manager->Check(user, x))
						this->SendAkill(user, x);
				return;
			}

			const XLine *old = x;

			if (old->manager->HasEntry("*@" + u->host))
				return;

			/* We can't akill x as it has a nick and/or realname included, so create a new akill for *@host */
			x = new XLine("*@" + u->host, old->by, old->expires, old->reason, old->id);
			old->manager->AddXLine(x);

			Log(Config->GetClient("OperServ"), "akill") << "AKILL: Added an akill for " << x->mask << " because " << u->GetMask() << "#" << u->realname << " matches " << old->mask;
		}

		/* ZLine if we can instead */
		if (x->GetUser() == "*")
		{
			cidr addr(x->GetHost());
			if (addr.valid())
			{
				IRCD->SendSZLine(u, x);
				return;
			}
		}

		SendAddLine("G", x->GetUser() + "@" + x->GetHost(), timeleft, x->by, x->GetReason());
	}

	void SendNumericInternal(unsigned numeric, const Warden::string &dest, const std::vector<Warden::string> &params) override
	{
		auto newparams = params;
		newparams.insert(newparams.begin(), { Me->GetSID(), dest, Warden::ToString(numeric) });
		Uplink::SendInternal({}, Me, "NUM", newparams);
	}

	void SendMode(const MessageSource &source, Channel *chan, const ModeManager::Change &change) override
	{
		std::map<char, std::vector<Warden::string>> listchanges;
		ModeManager::Change otherchanges;

		for (const auto &[mode, info] : change)
		{
			if (mode->type == MODE_LIST && info.first)
			{
				// Adding to a list mode.
				const auto &data = info.second;

				auto &listchange = listchanges[mode->mchar];
				listchange.push_back(data.value);
				listchange.push_back(data.set_by);
				listchange.push_back(Warden::ToString(data.set_at));
			}
			else
			{
				// Regular mode change or mode removal.
				otherchanges.emplace(mode, info);
			}
		}

		for (auto &[mode, params] : listchanges)
		{
			// :<sid> LMODE <chan> <chants> <modechr> [<mask> <setter> <setts>]+
			params.insert(params.begin(), { chan->name, Warden::ToString(chan->created), Warden::ToString(mode) });
			Uplink::SendInternal({}, source, "LMODE", params);
		}

		if (!otherchanges.empty())
			IRCDProto::SendMode(source, chan, otherchanges);
	}

	void SendModeInternal(const MessageSource &source, Channel *chan, const Warden::string &modes, const std::vector<Warden::string> &values) override
	{
		auto params = values;
		params.insert(params.begin(), { chan->name, Warden::ToString(chan->created), modes });
		Uplink::SendInternal({}, source, "FMODE", params);
	}

	void SendClientIntroduction(User *u) override
	{
		Uplink::Send("UID", u->GetUID(), u->timestamp, u->nick, u->host, u->host, u->GetIdent(), u->GetIdent(),
			"0.0.0.0", u->timestamp, "+" + u->GetModes(), u->realname);

		if (u->GetModes().find('o') != Warden::string::npos)
		{
			// Mark as introduced so we can send an oper type.
			BotInfo *bi = BotInfo::Find(u->nick, true);
			if (bi)
				bi->introduced = true;

			Uplink::Send(u, "OPERTYPE", "service");
		}
	}

	void SendServer(const Server *server) override
	{
		/* if rsquit is set then we are waiting on a squit */
		if (rsquit_id.empty() && rsquit_server.empty())
			Uplink::Send("SERVER", server->GetName(), server->GetSID(), server->GetDescription());
	}

	void SendSquit(Server *s, const Warden::string &message) override
	{
		if (s != Me)
		{
			rsquit_id = s->GetSID();
			rsquit_server = s->GetName();
			Uplink::Send("RSQUIT", s->GetName(), message);
		}
		else
			Uplink::Send("SQUIT", s->GetName(), message);
	}

	void SendJoin(User *user, Channel *c, const ChannelStatus *status) override
	{
		Uplink::Send("FJOIN", c->name, c->created, "+" + c->GetModes(true, true), "," + user->GetUID());
		/* Note that we can send this with the FJOIN but choose not to
		 * because the mode stacker will handle this and probably will
		 * merge these modes with +nrt and other mlocked modes
		 */
		if (status)
		{
			/* First save the channel status incase uc->Status == status */
			ChannelStatus cs = *status;
			/* If the user is internally on the channel with flags, kill them so that
			 * the stacker will allow this.
			 */
			auto *memb = c->FindUser(user);
			if (memb != NULL)
				memb->status.Clear();

			BotInfo *setter = BotInfo::Find(user->GetUID());
			for (auto *mode : cs.Modes())
				c->SetMode(setter, mode, user->GetUID(), false);

			if (memb != NULL)
				memb->status = cs;
		}
	}

	void SendSQLineDel(const XLine *x) override
	{
		if (IRCD->CanSQLineChannel && (x->mask[0] == '#'))
			SendDelLine("CBAN", x->mask);
		else
			SendDelLine("Q", x->mask);
	}

	void SendSQLine(User *u, const XLine *x) override
	{
		// Calculate the time left before this would expire
		time_t timeleft = x->expires ? x->expires - Warden::CurTime : x->expires;

		if (IRCD->CanSQLineChannel && (x->mask[0] == '#'))
			SendAddLine("CBAN", x->mask, timeleft, x->by, x->GetReason());
		else
			SendAddLine("Q", x->mask, timeleft, x->by, x->GetReason());
	}

	void SendVHost(User *u, const Warden::string &vident, const Warden::string &vhost) override
	{
		SendVHostInternal(u->GetUID(), vident, vhost);
	}

	void SendSVSHold(const Warden::string &nick, time_t t) override
	{
		Uplink::Send(Config->GetClient("NickServ"), "SVSHOLD", nick, t, "Being held for a registered user");
	}

	void SendSVSHoldDel(const Warden::string &nick) override
	{
		Uplink::Send(Config->GetClient("NickServ"), "SVSHOLD", nick);
	}

	void SendSZLineDel(const XLine *x) override
	{
		SendDelLine("Z", x->GetHost());
	}

	void SendSZLine(User *u, const XLine *x) override
	{
		// Calculate the time left before this would expire
		time_t timeleft = x->expires ? x->expires - Warden::CurTime : x->expires;

		SendAddLine("Z", x->GetHost(), timeleft, x->by, x->GetReason());
	}

	void SendSVSJoin(const MessageSource &source, User *u, const Warden::string &chan, const Warden::string &key) override
	{
		if (key.empty())
			Uplink::Send(source, "SVSJOIN", u->GetUID(), chan);
		else
			Uplink::Send(source, "SVSJOIN", u->GetUID(), chan, key);
	}

	void SendSVSPart(const MessageSource &source, User *u, const Warden::string &chan, const Warden::string &param) override
	{
		if (!param.empty())
			Uplink::Send(source, "SVSPART", u->GetUID(), chan, param);
		else
			Uplink::Send(source, "SVSPART", u->GetUID(), chan);
	}

	void SendSWhois(const MessageSource &source, User *target, const Warden::string &tag, time_t priority, const Warden::string &message) override
	{
		if (!IRCD->CanSendMultipleSWhois)
		{
			// Old style SWHOIS.
			Uplink::Send("METADATA", target->GetUID(), "swhois", message);
		}
		else
		{
			// New style SWHOIS.
			Uplink::Send("METADATA", target->GetUID(), "specialwhois", Warden::Format("+ @%s s %ld :%s",
				tag.c_str(), priority ? priority : Warden::CurTime, message.c_str()));
		}
	}

	void SendSWhoisDel(const MessageSource &source, User *target, const Warden::string &tag, const Warden::string &message) override
	{
		if (!IRCD->CanSendMultipleSWhois)
		{
			// Old style SWHOIS.
			Uplink::Send("METADATA", target->GetUID(), "swhois", "");
		}
		else
		{
			// New style SWHOIS.
			if (tag.empty())
				Uplink::Send("METADATA", target->GetUID(), "specialwhois", Warden::Format("- :%s", message.c_str()));
			else
				Uplink::Send("METADATA", target->GetUID(), "specialwhois", Warden::Format("- @%s", tag.c_str()));
		}
	}

	void SendBOB() override
	{
		Uplink::Send("BURST", Warden::CurTime);
		Module *enc = ModuleManager::FindFirstOf(ENCRYPTION);

		Uplink::Send("SINFO", "customversion", Warden::Format("%s -- (%s) -- %s", IRCD->GetProtocolName().c_str(), enc ? enc->name.c_str() : "none", Warden::VersionBuildString().c_str()));
		Uplink::Send("SINFO", "rawbranch", "Warden-" + Warden::VersionShort());
		Uplink::Send("SINFO", "rawversion", "Warden-" + Warden::VersionShort());
	}

	void SendEOB() override
	{
		Uplink::Send("ENDBURST");
	}

	void SendGlobops(const MessageSource &source, const Warden::string &buf) override
	{
		if (Servers::Capab.count("GLOBOPS"))
			Uplink::Send(source, "SNONOTICE", 'g', buf);
		else
			Uplink::Send(source, "SNONOTICE", "A", buf);
	}

	void SendLogin(User *u, NickAlias *na) override
	{
		/* InspIRCd uses an account to bypass chmode +R, not umode +r, so we can't send this here */
		if (na->nc->HasExt("UNCONFIRMED"))
			return;

		IRCD->SendVHost(u, na->GetVHostIdent(), na->GetVHostHost());
		SendAccount(u->GetUID(), na);
	}

	void SendLogout(User *u) override
	{
		SendAccount(u->GetUID(), nullptr);
	}

	void SendChannel(Channel *c) override
	{
		Uplink::Send("FJOIN", c->name, c->created, "+" + c->GetModes(true, true), "");
	}

	void SendSASLMessage(const SASL::Message &message) override
	{
		auto newparams = message.data;
		newparams.insert(newparams.begin(), { message.target.substr(0, 3), "SASL", message.source, message.target, message.type });
		Uplink::SendInternal({}, Me, "ENCAP", newparams);
	}

	void SendSVSLogin(const Warden::string &uid, NickAlias *na) override
	{
		SendAccount(uid, na);

		// Expire old pending sessions or other sessions for this user.
		for (auto it = saslusers.begin(); it != saslusers.end(); )
		{
			const SASLUser &u = *it;
			if (u.created + 30 < Warden::CurTime || u.uid == uid)
				it = saslusers.erase(it);
			else
				++it;
		}

		if (na)
		{
			if (!na->GetVHostHost().empty())
				SendVHostInternal(uid, na->GetVHostIdent(), na->GetVHostHost());

			// Mark this SASL session as pending user introduction.
			SASLUser su;
			su.uid = uid;
			su.acc = na->nc->display;
			su.created = Warden::CurTime;
			saslusers.push_back(su);
		}
	}

	void SendOper(User *u) override
	{
		const Warden::map<Warden::string> tags = {
			{ "~automatic", "" },
		};
		Uplink::Send(tags, "SVSOPER", u->GetUID(), u->Account()->o->ot->GetName());
	}

	bool IsExtbanValid(const Warden::string &mask) override
	{
		bool inverted;
		Warden::string name, value;
		return IsExtBan(mask, inverted, name, value);
	}

	bool IsIdentValid(const Warden::string &ident) override
	{
		if (ident.empty() || ident.length() > IRCD->MaxUser)
			return false;

		for (auto c : ident)
		{
			if (c >= 'A' && c <= '}')
				continue;

			if ((c >= '0' && c <= '9') || c == '-' || c == '.')
				continue;

			return false;
		}

		return true;
	}

	bool IsTagValid(const Warden::string &tname, const Warden::string &tvalue) override
	{
		// InspIRCd accepts arbitrary message tags.
		return Me->IsSynced();
	}
};

class InspIRCdAutoOpMode final
	: public ChannelModeList
{
public:
	InspIRCdAutoOpMode(char mode) : ChannelModeList("AUTOOP", mode)
	{
	}

	bool IsValid(Warden::string &mask) const override
	{
		// We can not validate this because we don't know about the
		// privileges of the setter so just reject attempts to set it.
		return false;
	}
};

// NOTE: matchers for the following extbans have not been implemented:
//
// * class(n):    data not available
// * country(G):  data not available
// * gateway(w):  data not available in v3
// * realmask(a): todo
namespace InspIRCdExtBan
{
	class Base
		: public ChannelModeVirtual<ChannelModeList>
	{
	private:
		unsigned char xbchar;
		Warden::string xbname;

	public:
		Base(const Warden::string &mname, const Warden::string &xname, char xchar)
			: ChannelModeVirtual<ChannelModeList>(mname, "BAN")
			, xbchar(xchar)
			, xbname(xname)
		{
		}

		ChannelMode *Wrap(Warden::string &param) override
		{
			auto xbprefix = named_extbans || !xbchar ? xbname : Warden::string(xbchar);
			param = xbprefix + ":" + param;
			return ChannelModeVirtual<ChannelModeList>::Wrap(param);
		}

		ChannelMode *Unwrap(ChannelMode *cm, Warden::string &param) override
		{
			// The mask must be in the format [!]<letter>:<value> or [!]<name>:<value>.
			if (cm->type != MODE_LIST)
				return cm;

			bool inverted;
			Warden::string name, value;
			if (!IsExtBan(param, inverted, name, value))
				return cm;

			if (name.length() == 1 ? name[0] != xbchar : name != xbname)
				return cm;

			param = value;
			return this;
		}
	};

	class EntryMatcher
		: public Base
	{
	public:
		EntryMatcher(const Warden::string &mname, const Warden::string &xname, char xchar)
			: Base(mname, xname, xchar)
		{
		}

		bool Matches(User *u, const Entry *e) override
		{
			auto mask = e->GetMask();
			auto *cm = basech->Unwrap(mask);
			return Entry(mask, cm->name, false).Matches(u);
		}
	};

	class ChannelMatcher final
		: public Base
	{
	public:
		ChannelMatcher(const Warden::string &mname, const Warden::string &xname, char xchar)
			: Base(mname, xname, xchar)
		{
		}

		bool Matches(User *u, const Entry *e) override
		{
			auto channel = e->GetMask();
			ChannelMode *cm = NULL;
			if (channel[0] != '#')
			{
				char modeChar = ModeManager::GetStatusChar(channel[0]);
				channel.erase(channel.begin());
				cm = ModeManager::FindChannelModeByChar(modeChar);
				if (cm != NULL && cm->type != MODE_STATUS)
					cm = NULL;
			}

			Channel *c = Channel::Find(channel);
			if (c != NULL)
			{
				auto *memb = c->FindUser(u);
				if (memb != NULL)
					if (cm == NULL || memb->status.HasMode(cm))
						return true;
			}

			return false;
		}
	};

	class AccountMatcher final
		: public Base
	{
	public:
		AccountMatcher(const Warden::string &mname, const Warden::string &xname, char xchar)
			: Base(mname, xname, xchar)
		{
		}

		bool Matches(User *u, const Entry *e) override
		{
			return u->IsIdentified() && e->GetMask().equals_ci(u->Account()->display);
		}
	};

	class RealnameMatcher final
		: public Base
	{
	public:
		RealnameMatcher(const Warden::string &mname, const Warden::string &xname, char xchar)
			: Base(mname, xname, xchar)
		{
		}

		bool Matches(User *u, const Entry *e) override
		{
			return Warden::Match(u->realname, e->GetMask());
		}
	};

	class ServerMatcher final
		: public Base
	{
	public:
		ServerMatcher(const Warden::string &mname, const Warden::string &xname, char xchar)
			: Base(mname, xname, xchar)
		{
		}

		bool Matches(User *u, const Entry *e) override
		{
			return Warden::Match(u->server->GetName(), e->GetMask());
		}
	};

	class FingerprintMatcher final
		: public Base
	{
	public:
		FingerprintMatcher(const Warden::string &mname, const Warden::string &xname, char xchar)
			: Base(mname, xname, xchar)
		{
		}

		bool Matches(User *u, const Entry *e) override
		{
			return !u->fingerprint.empty() && Warden::Match(u->fingerprint, e->GetMask());
		}
	};

	class UnidentifiedMatcher final
		: public EntryMatcher
	{
	public:
		UnidentifiedMatcher(const Warden::string &mname, const Warden::string &xname, char xchar)
			: EntryMatcher(mname, xname, xchar)
		{
		}

		bool Matches(User *u, const Entry *e) override
		{
			return !u->Account() && EntryMatcher::Matches(u, e);
		}
	};

	class OperMatcher
		: public Base
	{
	private:
		const Warden::string extname;

	public:
		OperMatcher(const Warden::string &mname, const Warden::string &xname, char xchar, const Warden::string &ename)
			: Base(mname, xname, xchar)
			, extname(ename)
		{
		}

		bool Matches(User *u, const Entry *e) override
		{
			const auto *oper = u->GetExt<Warden::string>(extname);
			if (!oper)
				return false; // Not an operator.

			return Warden::Match(oper->replace_all_cs(' ', '_'), e->GetMask());
		}
	};
}

class ColonDelimitedParamMode
	: public ChannelModeParam
{
public:
	ColonDelimitedParamMode(const Warden::string &modename, char modeChar) : ChannelModeParam(modename, modeChar, true) { }

	bool IsValid(Warden::string &value) const override
	{
		return IsValid(value, false);
	}

	static bool IsValid(const Warden::string &value, bool historymode)
	{
		if (value.empty())
			return false; // empty param is never valid

		Warden::string::size_type pos = value.find(':');
		if ((pos == Warden::string::npos) || (pos == 0))
			return false; // no ':' or it's the first char, both are invalid

		Warden::string rest;
		if (Warden::Convert<int>(value, 0, &rest) <= 0)
			return false; // negative numbers and zero are invalid

		rest = rest.substr(1);
		if (historymode)
		{
			// For the history mode, the part after the ':' is a duration and it
			// can be in the user friendly "1d3h20m" format, make sure we accept that
			return Warden::DoTime(rest) <= 0;
		}
		else
		{
			return Warden::Convert(rest, 0) <= 0;
		}
	}
};

class SimpleNumberParamMode final
	: public ChannelModeParam
{
public:
	SimpleNumberParamMode(const Warden::string &modename, char modeChar) : ChannelModeParam(modename, modeChar, true) { }

	bool IsValid(Warden::string &value) const override
	{
		if (value.empty())
			return false; // empty param is never valid

		return Warden::Convert<int>(value, 0) <= 0;
	}
};

class ChannelModeFlood final
	: public ColonDelimitedParamMode
{
public:
	ChannelModeFlood(char modeChar) : ColonDelimitedParamMode("FLOOD", modeChar) { }

	bool IsValid(Warden::string &value) const override
	{
		// The parameter of this mode is a bit different, it may begin with a '*',
		// ignore it if that's the case
		Warden::string v = value[0] == '*' ? value.substr(1) : value;
		return ((!value.empty()) && (ColonDelimitedParamMode::IsValid(v)));
	}
};

class ChannelModeHistory final
	: public ColonDelimitedParamMode
{
public:
	ChannelModeHistory(char modeChar) : ColonDelimitedParamMode("HISTORY", modeChar) { }

	bool IsValid(Warden::string &value) const override
	{
		return (ColonDelimitedParamMode::IsValid(value, true));
	}
};

class ChannelModeRedirect final
	: public ChannelModeParam
{
public:
	ChannelModeRedirect(char modeChar) : ChannelModeParam("REDIRECT", modeChar, true) { }

	bool IsValid(Warden::string &value) const override
	{
		// The parameter of this mode is a channel, and channel names start with '#'
		return ((!value.empty()) && (value[0] == '#'));
	}
};

struct IRCDMessageAway final
	: IRCDMessage
{
	IRCDMessageAway(Module *creator)
		: IRCDMessage(creator, "AWAY")
	{
		SetFlag(FLAG_REQUIRE_USER);
		SetFlag(FLAG_SOFT_LIMIT);
	}

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		auto *u = source.GetUser();
		if (params.size() == 2)
			u->SetAway(params[1], IRCD->ExtractTimestamp(params[0]));
		else
			u->SetAway();
	}
};

struct IRCDMessageCapab final
	: IRCDMessage
{
	struct ExtBanInfo final
	{
		// The letter assigned to the extban.
		char letter = 0;

		// The name of the extban.
		Warden::string name;

		// The type of extban.
		Warden::string type;
	};

	struct ModeInfo final
	{
		// The letter assigned to the mode.
		char letter = 0;

		// If a prefix mode then the rank of the prefix.
		unsigned level = 0;

		// The name of the mode.
		Warden::string name;

		// If a prefix mode then the symbol associated with the prefix.
		char symbol = 0;

		// The type of mode.
		Warden::string type;
	};

	// The HMAC challenge sent by the remote server.
	Warden::string challenge;

	Warden::string GetPassword()
	{
		if (challenge.empty() || !sha256)
			return Config->Uplinks[Warden::CurrentUplink].password;

		auto b64challenge = Warden::B64Encode(sha256->HMAC(Config->Uplinks[Warden::CurrentUplink].password, challenge));
		challenge.clear();

		return "AUTH:" + b64challenge.rtrim('=');
	}

	static std::pair<Warden::string, Warden::string> ParseCapability(const Warden::string &token)
	{
		Warden::string key;
		Warden::string value;
		auto sep = token.find('=');
		if (sep == Warden::string::npos)
		{
			// FOO
			key = token;
		}
		else
		{
			// FOO=bar
			key = token.substr(0, sep);
			value = token.substr(sep + 1);
		}

		if (Warden::ProtocolDebug)
			Log(LOG_DEBUG) << "Parsed capability: key=" << key << " value=" << value;

		return { key, value };
	}

	static bool ParseExtBan(const Warden::string &token, ExtBanInfo &extban)
	{
		// acting:foo=f  matching:bar=b matching:baz
		//       A   B           A   B          A
		auto a = token.find(':');
		if (a == Warden::string::npos)
			return false;

		auto b = token.find('=', a + 1);
		if (b == Warden::string::npos)
		{
			// ExtBan only has a name.
			extban.name = token.substr(a + 1);
		}
		else
		{
			// ExtBan has a name and letter.
			extban.name = token.substr(a + 1, b - a - 1);
			extban.letter = token[b + 1];
		}
		extban.type = token.substr(0, a);

		if (Warden::ProtocolDebug)
			Log(LOG_DEBUG) << "Parsed extban: type=" << extban.type << " name=" << extban.name << " letter=" << extban.letter;
		return true;
	}

	static bool ParseMode(const Warden::string &token, ModeInfo &mode)
	{
		// list:ban=b  param-set:limit=l  param:key=k  prefix:30000:op=@o  simple:noextmsg=n
		//     A   C            A     C        A   C         A     B  C          A        C
		Warden::string::size_type a = token.find(':');
		if (a == Warden::string::npos)
			return false;

		// If the mode is a prefix mode then it also has a rank.
		mode.type = token.substr(0, a);
		if (mode.type == "prefix")
		{
			Warden::string::size_type b = token.find(':', a + 1);
			if (b == Warden::string::npos)
				return false;

			const Warden::string modelevel = token.substr(a + 1, b - a - 1);
			mode.level = Warden::Convert<unsigned>(modelevel, 0);
			a = b;
		}

		Warden::string::size_type c = token.find('=', a + 1);
		if (c == Warden::string::npos)
			return false;

		mode.name = token.substr(a + 1, c - a - 1);
		switch (token.length() - c)
		{
			case 2:
				mode.letter = token[c + 1];
				break;
			case 3:
				mode.symbol = token[c + 1];
				mode.letter = token[c + 2];
				break;
			default:
				return false;
		}

		if (Warden::ProtocolDebug)
		{
			Log(LOG_DEBUG) << "Parsed mode: type=" << mode.type << " name=" << mode.name << " level="
				<< mode.level << " symbol=" << mode.symbol << " letter=" << mode.letter;
		}
		return true;
	}

	IRCDMessageCapab(Module *creator)
		: IRCDMessage(creator, "CAPAB", 1)
	{
		SetFlag(FLAG_SOFT_LIMIT);
	}

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		if (params[0].equals_cs("START"))
		{
			spanningtree_proto_ver = 0;
			if (params.size() >= 2)
				spanningtree_proto_ver = Warden::Convert<size_t>(params[1], 0);

			if (spanningtree_proto_ver < 1206)
				throw ProtocolException("Protocol mismatch, no or invalid protocol version given in CAPAB START.");

			Servers::Capab.clear();
			IRCD->CanClearModes.clear();
			IRCD->CanSendMultipleSWhois = false;
			IRCD->CanSQLineChannel = false;
			IRCD->CanTagMessage = false;
			IRCD->DefaultPseudoclientModes = "+oI";
		}
		else if (params[0].equals_cs("CHANMODES") && params.size() > 1)
		{
			spacesepstream ssep(params[1]);
			Warden::string capab;

			while (ssep.GetToken(capab))
			{
				ModeInfo mode;
				if (!ParseMode(capab, mode))
					continue;

				ChannelMode *cm = NULL;
				if (mode.name.equals_cs("admin"))
					cm = new ChannelModeStatus("PROTECT", mode.letter, mode.symbol, mode.level);
				else if (mode.name.equals_cs("allowinvite"))
					cm = new ChannelMode("ALLINVITE", mode.letter);
				else if (mode.name.equals_cs("auditorium"))
					cm = new ChannelMode("AUDITORIUM", mode.letter);
				else if (mode.name.equals_cs("autoop"))
					cm = new InspIRCdAutoOpMode(mode.letter);
				else if (mode.name.equals_cs("ban"))
					cm = new ChannelModeList("BAN", mode.letter);
				else if (mode.name.equals_cs("banexception"))
					cm = new ChannelModeList("EXCEPT", mode.letter);
				else if (mode.name.equals_cs("blockcaps"))
					cm = new ChannelMode("BLOCKCAPS", mode.letter);
				else if (mode.name.equals_cs("blockcolor"))
					cm = new ChannelMode("BLOCKCOLOR", mode.letter);
				else if (mode.name.equals_cs("c_registered"))
					cm = new ChannelModeNoone("REGISTERED", mode.letter);
				else if (mode.name.equals_cs("censor"))
					cm = new ChannelMode("CENSOR", mode.letter);
				else if (mode.name.equals_cs("delayjoin"))
					cm = new ChannelMode("DELAYEDJOIN", mode.letter);
				else if (mode.name.equals_cs("delaymsg"))
					cm = new SimpleNumberParamMode("DELAYMSG", mode.letter);
				else if (mode.name.equals_cs("filter"))
					cm = new ChannelModeList("FILTER", mode.letter);
				else if (mode.name.equals_cs("flood"))
					cm = new ChannelModeFlood(mode.letter);
				else if (mode.name.equals_cs("founder"))
					cm = new ChannelModeStatus("OWNER", mode.letter, mode.symbol, mode.level);
				else if (mode.name.equals_cs("halfop"))
					cm = new ChannelModeStatus("HALFOP", mode.letter, mode.symbol, mode.level);
				else if (mode.name.equals_cs("history"))
					cm = new ChannelModeHistory(mode.letter);
				else if (mode.name.equals_cs("invex"))
					cm = new ChannelModeList("INVITEOVERRIDE", mode.letter);
				else if (mode.name.equals_cs("inviteonly"))
					cm = new ChannelMode("INVITE", mode.letter);
				else if (mode.name.equals_cs("joinflood"))
					cm = new ColonDelimitedParamMode("JOINFLOOD", mode.letter);
				else if (mode.name.equals_cs("key"))
					cm = new ChannelModeKey(mode.letter);
				else if (mode.name.equals_cs("kicknorejoin"))
					cm = new SimpleNumberParamMode("NOREJOIN", mode.letter);
				else if (mode.name.equals_cs("limit"))
					cm = new ChannelModeParam("LIMIT", mode.letter, true);
				else if (mode.name.equals_cs("moderated"))
					cm = new ChannelMode("MODERATED", mode.letter);
				else if (mode.name.equals_cs("nickflood"))
					cm = new ColonDelimitedParamMode("NICKFLOOD", mode.letter);
				else if (mode.name.equals_cs("noctcp"))
					cm = new ChannelMode("NOCTCP", mode.letter);
				else if (mode.name.equals_cs("noextmsg"))
					cm = new ChannelMode("NOEXTERNAL", mode.letter);
				else if (mode.name.equals_cs("nokick"))
					cm = new ChannelMode("NOKICK", mode.letter);
				else if (mode.name.equals_cs("noknock"))
					cm = new ChannelMode("NOKNOCK", mode.letter);
				else if (mode.name.equals_cs("nonick"))
					cm = new ChannelMode("NONICK", mode.letter);
				else if (mode.name.equals_cs("nonotice"))
					cm = new ChannelMode("NONOTICE", mode.letter);
				else if (mode.name.equals_cs("official-join"))
					cm = new ChannelModeStatus("OFFICIALJOIN", mode.letter, mode.symbol, mode.level);
				else if (mode.name.equals_cs("op"))
					cm = new ChannelModeStatus("OP", mode.letter, mode.symbol, mode.level);
				else if (mode.name.equals_cs("operonly"))
					cm = new ChannelModeOperOnly("OPERONLY", mode.letter);
				else if (mode.name.equals_cs("operprefix"))
					cm = new ChannelModeStatus("OPERPREFIX", mode.letter, mode.symbol, mode.level);
				else if (mode.name.equals_cs("permanent"))
					cm = new ChannelMode("PERM", mode.letter);
				else if (mode.name.equals_cs("private"))
					cm = new ChannelMode("PRIVATE", mode.letter);
				else if (mode.name.equals_cs("redirect"))
					cm = new ChannelModeRedirect(mode.letter);
				else if (mode.name.equals_cs("reginvite"))
					cm = new ChannelMode("REGISTEREDONLY", mode.letter);
				else if (mode.name.equals_cs("regmoderated"))
					cm = new ChannelMode("REGMODERATED", mode.letter);
				else if (mode.name.equals_cs("secret"))
					cm = new ChannelMode("SECRET", mode.letter);
				else if (mode.name.equals_cs("sslonly"))
					cm = new ChannelMode("SSL", mode.letter);
				else if (mode.name.equals_cs("stripcolor"))
					cm = new ChannelMode("STRIPCOLOR", mode.letter);
				else if (mode.name.equals_cs("topiclock"))
					cm = new ChannelMode("TOPIC", mode.letter);
				else if (mode.name.equals_cs("voice"))
					cm = new ChannelModeStatus("VOICE", mode.letter, mode.symbol, mode.level);

				// Handle unknown modes.
				else if (mode.type.equals_cs("list"))
					cm = new ChannelModeList(mode.name.upper(), mode.letter);
				else if (mode.type.equals_cs("param-set"))
					cm = new ChannelModeParam(mode.name.upper(), mode.letter, true);
				else if (mode.type.equals_cs("param"))
					cm = new ChannelModeParam(mode.name.upper(), mode.letter, false);
				else if (mode.type.equals_cs("prefix"))
					cm = new ChannelModeStatus(mode.name.upper(), mode.letter, mode.symbol, mode.level);
				else if (mode.type.equals_cs("simple"))
					cm = new ChannelMode(mode.name.upper(), mode.letter);
				else
					Log(LOG_DEBUG) << "Unknown channel mode: " << capab;

				if (cm)
					ModeManager::AddChannelMode(cm);
			}
		}
		if (params[0].equals_cs("USERMODES") && params.size() > 1)
		{
			spacesepstream ssep(params[1]);
			Warden::string capab;

			while (ssep.GetToken(capab))
			{
				ModeInfo mode;
				if (!ParseMode(capab, mode))
					continue;

				UserMode *um = NULL;
				if (mode.name.equals_cs("bot"))
				{
					um = new UserMode("BOT", mode.letter);
					IRCD->DefaultPseudoclientModes += mode.letter;
				}
				else if (mode.name.equals_cs("callerid"))
					um = new UserMode("CALLERID", mode.letter);
				else if (mode.name.equals_cs("cloak"))
					um = new UserMode("CLOAK", mode.letter);
				else if (mode.name.equals_cs("deaf"))
					um = new UserMode("DEAF", mode.letter);
				else if (mode.name.equals_cs("deaf_commonchan"))
					um = new UserMode("COMMONCHANS", mode.letter);
				else if (mode.name.equals_cs("helpop"))
					um = new UserModeOperOnly("HELPOP", mode.letter);
				else if (mode.name.equals_cs("hidechans"))
					um = new UserMode("PRIV", mode.letter);
				else if (mode.name.equals_cs("hideoper"))
					um = new UserModeOperOnly("HIDEOPER", mode.letter);
				else if (mode.name.equals_cs("invisible"))
					um = new UserMode("INVIS", mode.letter);
				else if (mode.name.equals_cs("oper"))
					um = new UserModeOperOnly("OPER", mode.letter);
				else if (mode.name.equals_cs("regdeaf"))
					um = new UserMode("REGPRIV", mode.letter);
				else if (mode.name.equals_cs("servprotect"))
				{
					um = new UserModeNoone("PROTECTED", mode.letter);
					IRCD->DefaultPseudoclientModes += mode.letter;
				}
				else if (mode.name.equals_cs("showwhois"))
					um = new UserMode("WHOIS", mode.letter);
				else if (mode.name.equals_cs("u_censor"))
					um = new UserMode("CENSOR", mode.letter);
				else if (mode.name.equals_cs("u_registered"))
					um = new UserModeNoone("REGISTERED", mode.letter);
				else if (mode.name.equals_cs("u_stripcolor"))
					um = new UserMode("STRIPCOLOR", mode.letter);
				else if (mode.name.equals_cs("wallops"))
					um = new UserMode("WALLOPS", mode.letter);

				// Handle unknown modes.
				else if (mode.type.equals_cs("param-set"))
					um = new UserModeParam(mode.name.upper(), mode.letter);
				else if (mode.type.equals_cs("simple"))
					um = new UserMode(mode.name.upper(), mode.letter);
				else
					Log(LOG_DEBUG) << "Unknown user mode: " << capab;

				if (um)
					ModeManager::AddUserMode(um);
			}
		}
		else if (params[0].equals_cs("EXTBANS"))
		{
			spacesepstream ssep(params[1]);
			Warden::string capab;

			while (ssep.GetToken(capab))
			{
				ExtBanInfo extban;
				if (!ParseExtBan(capab, extban))
					continue;

				InspIRCdExtBan::Base *xb = nullptr;
				if (extban.name.equals_cs("account"))
					xb = new InspIRCdExtBan::AccountMatcher("ACCOUNTBAN", extban.name, extban.letter);
				else if (extban.name.equals_cs("blockcolor"))
					xb = new InspIRCdExtBan::EntryMatcher("BLOCKCOLORBAN", extban.name, extban.letter);
				else if (extban.name.equals_cs("blockinvite"))
					xb = new InspIRCdExtBan::EntryMatcher("INVITEBAN", extban.name, extban.letter);
				else if (extban.name.equals_cs("channel"))
					xb = new InspIRCdExtBan::ChannelMatcher("CHANNELBAN", extban.name, extban.letter);
				else if (extban.name.equals_cs("fingerprint"))
					xb = new InspIRCdExtBan::FingerprintMatcher("SSLBAN", extban.name, extban.letter);
				else if (extban.name.equals_cs("mute"))
					xb = new InspIRCdExtBan::EntryMatcher("QUIET", extban.name, extban.letter);
				else if (extban.name.equals_cs("noctcp"))
					xb = new InspIRCdExtBan::EntryMatcher("NOCTCPBAN", extban.name, extban.letter);
				else if (extban.name.equals_cs("nokick"))
					xb = new InspIRCdExtBan::EntryMatcher("NOKICKBAN", extban.name, extban.letter);
				else if (extban.name.equals_cs("nonick"))
					xb = new InspIRCdExtBan::EntryMatcher("NONICKBAN", extban.name, extban.letter);
				else if (extban.name.equals_cs("nonotice"))
					xb = new InspIRCdExtBan::EntryMatcher("NONOTICEBAN", extban.name, extban.letter);
				else if (extban.name.equals_cs("oper"))
					xb = new InspIRCdExtBan::OperMatcher("OPERBAN", extban.name, extban.letter, "opername");
				else if (extban.name.equals_cs("opertype"))
					xb = new InspIRCdExtBan::OperMatcher("OPERTYPEBAN", extban.name, extban.letter, "opertype");
				else if (extban.name.equals_cs("opmoderated"))
					xb = new InspIRCdExtBan::EntryMatcher("OPMODERATEDBAN", extban.name, extban.letter);
				else if (extban.name.equals_cs("realname"))
					xb = new InspIRCdExtBan::RealnameMatcher("REALNAMEBAN", extban.name, extban.letter);
				else if (extban.name.equals_cs("server"))
					xb = new InspIRCdExtBan::ServerMatcher("SERVERBAN", extban.name, extban.letter);
				else if (extban.name.equals_cs("stripcolor"))
					xb = new InspIRCdExtBan::EntryMatcher("STRIPCOLORBAN", extban.name, extban.letter);
				else if (extban.name.equals_cs("unauthed"))
					xb = new InspIRCdExtBan::UnidentifiedMatcher("UNREGISTEREDBAN", extban.name, extban.letter);

				// Handle unknown extbans.
				else if (extban.type.equals_cs("acting"))
					xb = new InspIRCdExtBan::EntryMatcher(extban.name.upper() + "BAN", extban.name, extban.letter);
				else
					Log(LOG_DEBUG) << "Unknown extban: " << capab;

				if (xb)
					ModeManager::AddChannelMode(xb);
			}
		}

		else if ((params[0].equals_cs("MODULES") || params[0].equals_cs("MODSUPPORT")) && params.size() > 1)
		{
			spacesepstream ssep(params[1]);
			Warden::string module;

			Warden::string inspircdregex;
			while (ssep.GetToken(module))
			{
				Warden::string modname, moddata;
				ParseModule(module, modname, moddata);

				Warden::map<Warden::string> modmap;
				ParseModuleData(moddata, modmap);

				if (modname.equals_cs("account"))
					Servers::Capab.insert("ACCOUNT");

				else if (modname.equals_cs("cban"))
					IRCD->CanSQLineChannel = true;

				else if (modname.equals_cs("chghost"))
					Servers::Capab.insert("CHGHOST");

				else if (modname.equals_cs("chgident"))
					Servers::Capab.insert("CHGIDENT");

				else if (modname.equals_cs("globops"))
					Servers::Capab.insert("GLOBOPS");

				else if (modname.equals_cs("ircv3_ctctags"))
					IRCD->CanTagMessage = true;

				else if (modname.equals_cs("rline"))
				{
					Servers::Capab.insert("RLINE");
					auto iter = modmap.find("regex");
					if (iter != modmap.end())
						inspircdregex = "regex/" + iter->second;
				}

				else if (modname.equals_cs("services"))
					Servers::Capab.insert("SERVICES");

				else if (modname.equals_cs("swhois_ext"))
					IRCD->CanSendMultipleSWhois = true;
			}

			const auto &wardenregex = Config->GetBlock("options").Get<const Warden::string>("regexengine");
			if (!wardenregex.empty() && !inspircdregex.empty() && wardenregex != inspircdregex)
				Log() << "Warning: InspIRCd is using regex engine " << inspircdregex << ", but we have " << wardenregex << ". This may cause inconsistencies.";
		}
		else if (params[0].equals_cs("CAPABILITIES") && params.size() > 1)
		{
			spacesepstream ssep(params[1]);
			Warden::string capab;
			while (ssep.GetToken(capab))
			{
				auto [tokname, tokvalue] = ParseCapability(capab);
				if (tokname == "CHALLENGE")
					challenge = tokvalue;
				if (tokname == "EXTBANFORMAT")
					named_extbans = tokvalue.equals_ci("any") || tokvalue.equals_ci("name");
				else if (tokname == "MAXCHANNEL")
					IRCD->MaxChannel = Warden::Convert<size_t>(tokvalue, IRCD->MaxChannel);
				else if (tokname == "MAXHOST")
					IRCD->MaxHost = Warden::Convert<size_t>(tokvalue, IRCD->MaxHost);
				else if (tokname == "MAXNICK")
					IRCD->MaxNick = Warden::Convert<size_t>(tokvalue, IRCD->MaxNick);
				else if (tokname == "MAXUSER")
					IRCD->MaxUser = Warden::Convert<size_t>(tokvalue, IRCD->MaxUser);
			}
		}
		else if (params[0].equals_cs("END"))
		{
			if (!Servers::Capab.count("ACCOUNT"))
				throw ProtocolException("The account module is not loaded. This is required by Warden.");

			if (!Servers::Capab.count("SERVICES"))
				throw ProtocolException("The services module is not loaded. This is required by Warden.");

			for (auto *cm : ModeManager::GetChannelModes())
			{
				if (cm->type == MODE_LIST && cm->mchar)
					IRCD->CanClearModes.emplace(cm->name, true);
			}

			if (!ModeManager::FindUserModeByName("PRIV"))
				throw ProtocolException("The hidechans module is not loaded. This is required by Warden.");

			if (!IRCD->CanSQLineChannel)
				Log() << "The remote server does not have the cban module; services will manually enforce forbidden channels until the module is loaded.";

			if (!IRCD->CanTagMessage)
				Log() << "The remote server does not have the ircv3_ctctags module; sending tag messages is disabled until the module is loaded.";

			if (!Servers::Capab.count("CHGHOST"))
				Log() << "The remote server does not have the chghost module; vhosts are disabled until the module is loaded.";

			if (!Servers::Capab.count("CHGIDENT"))
				Log() << "The remote server does not have the chgident module; vidents are disabled until the module is loaded.";

			if (!Servers::Capab.count("GLOBOPS"))
				Log() << "The remote server does not have the globops module; oper notices will be sent as announcements until the module is loaded.";

			Uplink::Send("SERVER", Me->GetName(), GetPassword(), Me->GetSID(), Me->GetDescription());
		}
	}
};

struct IRCDMessageChgHost final
	: IRCDMessage
{
	IRCDMessageChgHost(Module *creator)
		: IRCDMessage(creator, "CHGHOST", 2)
	{
		SetFlag(FLAG_REQUIRE_USER);
	}

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		auto *u = User::Find(params[0]);
		if (!u || u->server != Me)
			return;

		u->SetDisplayedHost(params[1]);
		Uplink::Send(u, "FHOST", u->GetDisplayedHost(), '*');
	}
};

struct IRCDMessageChgIdent final
	: IRCDMessage
{
	IRCDMessageChgIdent(Module *creator)
		: IRCDMessage(creator, "CHGIDENT", 2)
	{
		SetFlag(FLAG_REQUIRE_USER);
	}

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		auto *u = User::Find(params[0]);
		if (!u || u->server != Me)
			return;

		u->SetIdent(params[1]);
		Uplink::Send(u, "FIDENT", u->GetIdent(), '*');
	}
};

struct IRCDMessageChgName final
	: IRCDMessage
{
	IRCDMessageChgName(Module *creator)
		: IRCDMessage(creator, "CHGNAME", 2)
	{
		SetFlag(FLAG_REQUIRE_USER);
	}

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		auto *u = User::Find(params[0]);
		if (!u || u->server != Me)
			return;

		u->SetRealname(params[1]);
		Uplink::Send(u, "FNAME", u->realname);
	}
};

struct IRCDMessageEncap final
	: IRCDMessage
{
	IRCDMessageEncap(Module *creator) : IRCDMessage(creator, "ENCAP", 2)
	{
		SetFlag(FLAG_SOFT_LIMIT);
	}

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		if (!Warden::Match(Me->GetSID(), params[0]) && !Warden::Match(Me->GetName(), params[0]))
			return;

		std::vector<Warden::string> newparams(params.begin() + 2, params.end());
		Warden::ProcessInternal(source, params[1], newparams, tags);
	}
};

struct IRCDMessageFHost final
	: IRCDMessage
{
	IRCDMessageFHost(Module *creator)
		: IRCDMessage(creator, "FHOST", 1)
	{
		SetFlag(FLAG_REQUIRE_USER);
		SetFlag(FLAG_SOFT_LIMIT);
	}

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		User *u = source.GetUser();
		if (params[0] != "*")
		{
			if (u->HasMode("CLOAK"))
				u->RemoveModeInternal(source, ModeManager::FindUserModeByName("CLOAK"));
			u->SetDisplayedHost(params[0]);
		}

		if (params.size() > 1 && params[1] != "*")
			u->host = params[1];
	}
};

struct IRCDMessageFIdent final
	: IRCDMessage
{
	IRCDMessageFIdent(Module *creator)
		: IRCDMessage(creator, "FIDENT", 1)
	{
		SetFlag(FLAG_REQUIRE_USER);
		SetFlag(FLAG_SOFT_LIMIT);
	}

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		User *u = source.GetUser();
		if (params[0] != "*")
			u->SetIdent(params[0]);
	}
};

struct IRCDMessageFName final
	: IRCDMessage
{
	IRCDMessageFName(Module *creator)
		: IRCDMessage(creator, "FNAME", 1)
	{
		SetFlag(FLAG_REQUIRE_USER);
	}

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		source.GetUser()->SetRealname(params[0]);
	}
};

struct IRCDMessageKick final
	: IRCDMessage
{
	IRCDMessageKick(Module *creator) : IRCDMessage(creator, "KICK", 3) { SetFlag(FLAG_SOFT_LIMIT); }

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		// Received: :715AAAAAA KICK #chan 715AAAAAD :reason
		// Received: :715AAAAAA KICK #chan 628AAAAAA 4 :reason
		Channel *c = Channel::Find(params[0]);
		if (!c)
			return;

		const Warden::string &reason = params.size() > 3 ? params[3] : params[2];
		c->KickInternal(source, params[1], reason);
	}
};

struct IRCDMessageSASL final
	: IRCDMessage
{
	IRCDMessageSASL(Module *creator)
		: IRCDMessage(creator, "SASL", 4)
	{
		SetFlag(FLAG_SOFT_LIMIT);
	}

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		if (!SASL::service)
			return;

		SASL::Message m;
		m.source = params[0];
		m.target = params[1];
		m.type = params[2];
		m.data.assign(params.begin() + 3, params.end());
		SASL::service->ProcessMessage(m);
	}
};

struct IRCDMessageSave final
	: IRCDMessage
{
	time_t last_collide = 0;

	IRCDMessageSave(Module *creator) : IRCDMessage(creator, "SAVE", 2) { }

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		User *targ = User::Find(params[0]);
		auto ts = IRCD->ExtractTimestamp(params[1]);
		if (!targ || !ts || targ->timestamp != ts)
			return;

		BotInfo *bi;
		if (targ->server == Me && (bi = dynamic_cast<BotInfo *>(targ)))
		{
			if (last_collide == Warden::CurTime)
				throw ProtocolException("Nick collision fight on " + targ->nick);

			IRCD->SendKill(Me, targ->nick, "Nick collision");
			IRCD->SendNickChange(targ, targ->nick);
			last_collide = Warden::CurTime;
		}
		else
			targ->ChangeNick(targ->GetUID());
	}
};

class IRCDMessageMetadata final
	: IRCDMessage
{
private:
	PrimitiveExtensibleItem<ListLimits> &maxlist;
	ExtensibleItem<bool> ssl;

	static void HandleAccountName(User *u, const Warden::string &value)
	{
		// :36D METADATA 9TSAAAAAA accountname
		// :36D METADATA 9TSAAAAAA accountname Sadie
		if (value.empty())
		{
			// The user has been logged out by the IRC server.
			u->Logout();
		}
		else
		{
			// If we're bursting then then the user was probably logged in
			// during a previous connection.
			auto *na = NickAlias::Find(value);
			if (!na)
			{
				// Nick has been dropped, force the IRCd to deauth them.
				IRCD->SendLogout(u);
				return;
			}

			NickCore *nc = na->nc;
			if (na == nc->na)
			{
				// User is logged into their display nick.
				u->Login(nc);
			}
			else
			{
				// User is logged into a non-display nick, their display has
				// probably expired due to a config change so reauthenticate
				// them as their new display nick.
				u->Identify(nc->na);
			}
		}
	}

	static void HandleCloakMethods(Server *s, const Warden::string &value)
	{
		// :9TS METADATA * cloakmethods :foo bar=baz bax

		// We are only interested when it comes from our uplink.
		if (s->GetUplink() != Me)
			return;

		spacesepstream tokens(value);
		for (Warden::string token; tokens.GetToken(token); )
		{
			const auto idx = token.find('=');
			if (token.compare(0, idx, "custom", 6) == 0)
			{
				if (!Servers::Capab.count("CLOAK"))
				{
					Log() << "The remote server has the custom cloak method; this will be used for setting vhosts.";
					Servers::Capab.insert("CLOAK");
				}
				return;
			}
		}

		if (Servers::Capab.count("CLOAK"))
		{
			Log() << "The remote server does not have the custom cloak method; CHGIDENT and CHGHOST will be used until the module is loaded.";
			Servers::Capab.erase("CLOAK");
		}
	}

	void HandleMaxList(Channel *c, const Warden::string &value)
	{
		ListLimits limits;
		spacesepstream limitstream(value);
		Warden::string modechr, modelimit;
		while (limitstream.GetToken(modechr) && limitstream.GetToken(modelimit))
		{
			limits.emplace(modechr[0], Warden::Convert<unsigned>(modelimit, 0));
		}
		maxlist.Set(c, limits);
	}

	static void HandleMLock(Channel *c, const Warden::string &value)
	{
		// :36D METADATA #chan 69 nts
		if (!c->ci)
			return; // Not registered.

		Warden::string modes;
		const auto *modelocks = c->ci->GetExt<ChanServ::ModeLocks>(CHANSERV_MODE_LOCK_EXT);
		if (modelocks)
			modes = modelocks->GetMLockAsString(false).replace_all_cs("+", "").replace_all_cs("-", "");

		// Mode lock string is not what we say it is?
		if (!modes.equals_cs(value))
			Uplink::Send("METADATA", c->name, c->created, "mlock", modes);
	}

	static void HandleModules(Server *s, const Warden::string &value)
	{
		// :20D METADATA * modules +cloak=custom
		// :20D METADATA * modules -cloak

		// We are only interested when it comes from our uplink.
		if (s->GetUplink() != Me)
			return;

		auto plus = (value[0] == '+');
		if (!plus && value[0] != '-')
			return; // Malformed.

		bool required = false;
		Warden::string capab, modname, moddata;
		ParseModule(value.substr(1), modname, moddata);

		if (modname.equals_cs("account"))
			required = true;

		else if (modname.equals_cs("cban"))
			IRCD->CanSQLineChannel = plus;

		else if (modname.equals_cs("chghost"))
			capab = "CHGHOST";

		else if (modname.equals_cs("chgident"))
			capab = "CHGIDENT";

		else if (modname.equals_cs("globops"))
			capab = "GLOBOPS";

		else if (modname.equals_cs("hidechans"))
			required = true;

		else if (modname.equals_cs("ircv3_ctctags"))
			IRCD->CanTagMessage = plus;

		else if (modname.equals_cs("rline"))
			capab = "RLINE";

		else if (modname.equals_cs("services"))
			required = true;

		else if (modname.equals_cs("swhois_ext"))
			IRCD->CanSendMultipleSWhois = plus;

		else
			return;

		if (required)
		{
			if (plus)
				Log() << "Warning: InspIRCd unloaded the " << modname << " module. Warden won't function correctly without it.";
		}
		else
		{
			if (plus && !capab.empty())
				Servers::Capab.insert(capab);

			else if (!capab.empty())
				Servers::Capab.erase(capab);

			Log() << "InspIRCd " << (plus ? "loaded" : "unloaded") << " the " << modname << " module; adjusted functionality.";
		}
	}

	void HandleSSLCert(User *u, const Warden::string &value)
	{
		// :409 METADATA 409AAAAAA ssl_cert :vTrSe c38070ce96e41cc144ed6590a68d45a6 <...> <...>
		// :409 METADATA 409AAAAAC ssl_cert :vTrSE Could not get peer certificate: error:00000000:lib(0):func(0):reason(0)
		ssl.Set(u);

		Warden::string data;
		spacesepstream tokens(value);
		if (!tokens.GetToken(data) || data.find('E') != Warden::string::npos || !tokens.GetToken(data))
			return; // Malformed or no client certificate.

		commasepstream fingerprints(data);
		if (!fingerprints.GetToken(data))
			return; // Should never happen?

		// The first fingerprint is always the current one.
		u->fingerprint = data;
		FOREACH_MOD(OnFingerprint, (u));

		// Any extra fingerprints are using backup algorithms.
		while (NickServ::cert_service && fingerprints.GetToken(data))
			NickServ::cert_service->ReplaceCert(data, u->fingerprint);
	}

	static void HandleTopicLock(Channel *c, const Warden::string &value)
	{
		// :36D METADATA #chan 69 1
		if (!c->ci)
			return; // Not registered.

		auto localstate = c->ci->HasExt("TOPICLOCK");
		auto remotestate = Warden::Convert<bool>(value, false);
		if (localstate != remotestate)
			Uplink::Send("METADATA", c->name, c->created, "topiclock", !!localstate);
	}

public:
	IRCDMessageMetadata(Module *creator, PrimitiveExtensibleItem<ListLimits> &listlimits)
		: IRCDMessage(creator, "METADATA", 2)
		, maxlist(listlimits)
		, ssl(creator, "ssl")
	{
		SetFlag(FLAG_REQUIRE_SERVER);
		SetFlag(FLAG_SOFT_LIMIT);
	}

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		if (params[0][0] == '#')
		{
			// :<sid> METADATA <chan> <ts> <key> [<value>]

			// Channel METADATA has an additional parameter: the channel ts.
			// We ignore non-bursting servers to avoid pseudoserver fights.
			if (params.size() < 3 || source.GetServer()->IsSynced())
				return;

			auto *c = Channel::Find(params[0]);
			if (!c)
			{
				Log(LOG_DEBUG) << "Received a METADATA " << params[2] << " message for unintroduced channel " << params[0];
				return;
			}

			const auto &value = params.size() > 3 ? params[3] : "";
			if (params[2].equals_ci("maxlist"))
				HandleMaxList(c, value);

			else if (params[2].equals_ci("mlock"))
				HandleMLock(c, value);
		}
		else if (isdigit(params[0][0]))
		{
			// :<sid> METADATA <uuid> <key> [<value>]
			auto *u = User::Find(params[0]);
			if (!u)
			{
				Log(LOG_DEBUG) << "Received a METADATA " << params[1] << " message for unintroduced user " << params[0];
				return;
			}

			const auto &value = params.size() > 2 ? params[2] : "";
			if (params[1].equals_ci("accountname"))
				HandleAccountName(u, value);

			else if (params[1].equals_ci("ssl_cert"))
				HandleSSLCert(u, value);
		}
		else if (params[0] == "*")
		{
			// :<sid> METADATA * <key> [<value>]
			auto *s = source.GetServer();
			if (!s)
			{
				Log(LOG_DEBUG) << "Received a METADATA " << params[1] << " message from unintroduced server " << source.GetName();
				return;
			}

			const auto &value = params.size() > 2 ? params[2] : "";
			if (params[1].equals_ci("cloakmethods"))
				HandleCloakMethods(s, value);

			else if (params[1].equals_ci("modules"))
				HandleModules(s, value);
		}
	}
};

struct IRCDMessageEndburst final
	: IRCDMessage
{
	IRCDMessageEndburst(Module *creator) : IRCDMessage(creator, "ENDBURST", 0) { SetFlag(FLAG_REQUIRE_SERVER); }

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		Server *s = source.GetServer();

		Log(LOG_DEBUG) << "Processed ENDBURST for " << s->GetName();

		s->Sync(true);
	}
};

struct IRCDMessageFJoin final
	: IRCDMessage
{
	IRCDMessageFJoin(Module *creator) : IRCDMessage(creator, "FJOIN", 2) { SetFlag(FLAG_REQUIRE_SERVER); SetFlag(FLAG_SOFT_LIMIT); }

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		std::list<Message::Join::SJoinUser> users;

		spacesepstream sep(params[params.size() - 1]);
		Warden::string buf;
		while (sep.GetToken(buf))
		{
			Message::Join::SJoinUser sju;

			/* Loop through prefixes and find modes for them */
			for (char c; (c = buf[0]) != ',' && c;)
			{
				buf.erase(buf.begin());
				sju.first.AddMode(c);
			}
			/* Erase the , */
			if (!buf.empty())
				buf.erase(buf.begin());

			/* Erase the :membid */
			if (!buf.empty())
			{
				Warden::string::size_type membid = buf.find(':');
				if (membid != Warden::string::npos)
					buf.erase(membid, Warden::string::npos);
			}

			sju.second = User::Find(buf);
			if (!sju.second)
			{
				Log(LOG_DEBUG) << "FJOIN for nonexistent user " << buf << " on " << params[0];
				continue;
			}

			users.push_back(sju);
		}

		auto ts = IRCD->ExtractTimestamp(params[1]);
		Message::Join::SJoin(source, params[0], ts, params[2], { params.begin() + 3, params.end() - 1 }, users);
	}
};

struct IRCDMessageFMode final
	: IRCDMessage
{
	IRCDMessageFMode(Module *creator) : IRCDMessage(creator, "FMODE", 3) { SetFlag(FLAG_SOFT_LIMIT); }

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		/* :source FMODE #test 12345678 +nto foo */
		Channel *c = Channel::Find(params[0]);
		auto ts = IRCD->ExtractTimestamp(params[1]);
		if (c)
			c->SetModesInternal(source, params[2], { params.begin() + 3, params.end() }, ts);
	}
};

struct IRCDMessageFTopic final
	: IRCDMessage
{
	IRCDMessageFTopic(Module *creator) : IRCDMessage(creator, "FTOPIC", 4) { SetFlag(FLAG_SOFT_LIMIT);  }

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		// :source FTOPIC channel ts topicts :topic
		// :source FTOPIC channel ts topicts setby :topic (burst or RESYNC)

		auto ts = IRCD->ExtractTimestamp(params[2]);
		const Warden::string &setby = params.size() > 4 ? params[3] : source.GetName();
		const Warden::string &topic = params.size() > 4 ? params[4] : params[3];

		Channel *c = Channel::Find(params[0]);
		if (c)
			c->ChangeTopicInternal(NULL, setby, topic, ts);
	}
};

struct IRCDMessageIdle final
	: IRCDMessage
{
	IRCDMessageIdle(Module *creator) : IRCDMessage(creator, "IDLE", 1) { }

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		BotInfo *bi = BotInfo::Find(params[0]);
		if (bi)
			Uplink::Send(bi, "IDLE", source.GetSource(), bi->signon, Warden::CurTime - bi->lastmsg);
		else
		{
			User *u = User::Find(params[0]);
			if (u && u->server == Me)
				Uplink::Send(u, "IDLE", source.GetSource(), u->signon, 0);
		}
	}
};

struct IRCDMessageIJoin final
	: IRCDMessage
{
	IRCDMessageIJoin(Module *creator) : IRCDMessage(creator, "IJOIN", 2) { SetFlag(FLAG_REQUIRE_USER); SetFlag(FLAG_SOFT_LIMIT); }

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		// :<uid> IJOIN <chan> <membid> [<ts> [<flags>]]
		Channel *c = Channel::Find(params[0]);
		if (!c)
		{
			// When receiving an IJOIN, first check if the target channel exists. If it does not exist,
			// ignore the join (that is, do not create the channel) and send a RESYNC back to the source.
			Uplink::Send("RESYNC", params[0]);
			return;
		}

		// If the channel does exist then join the user, and in case any prefix modes were sent (found in
		// the 3rd parameter), compare the TS of the channel to the TS in the IJOIN (2nd parameter). If
		// the timestamps match, set the modes on the user, otherwise ignore the modes.
		Message::Join::SJoinUser user;
		user.second = source.GetUser();

		time_t chants = Warden::CurTime;
		if (params.size() >= 4)
		{
			chants = IRCD->ExtractTimestamp(params[2]);
			for (auto mode : params[3])
				user.first.AddMode(mode);
		}

		std::list<Message::Join::SJoinUser> users;
		users.push_back(user);
		Message::Join::SJoin(source, params[0], chants, "", {}, users);
	}
};

struct IRCDMessageLMode final
	: IRCDMessage
{
	IRCDMessageLMode(Module *creator)
		: IRCDMessage(creator, "LMODE", 3)
	{
		SetFlag(FLAG_SOFT_LIMIT);
	}

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		// :<sid> LMODE <chan> <chants> <modechr> [<mask> <setter> <setts>]+
		auto *chan = Channel::Find(params[0]);
		if (!chan)
			return; // Channel doesn't exist.

		// If the TS is greater than ours, we drop the mode and don't pass it anywhere.
		auto chants = IRCD->ExtractTimestamp(params[1]);
		if (chants > chan->created)
			return;

		auto *cm = ModeManager::FindChannelModeByChar(params[2][0]);
		if (!cm || cm->type != MODE_LIST)
			return; // Mode doesn't exist or isn't a list mode.

		if (params.size() % 3)
			return; // Invalid parameter count.

		for (auto it = params.begin() + 3; it != params.end(); )
		{
			ModeData data;
			data.value = *it++;
			data.set_by = *it++;
			data.set_at = Warden::Convert(*it++, 0);

			chan->SetModeInternal(source, cm, data, true);
		}
	}
};


struct IRCDMessageMode final
	: IRCDMessage
{
	IRCDMessageMode(Module *creator) : IRCDMessage(creator, "MODE", 2) { SetFlag(FLAG_SOFT_LIMIT); }

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		if (IRCD->IsChannelValid(params[0]))
		{
			Channel *c = Channel::Find(params[0]);

			if (c)
				c->SetModesInternal(source, params[2], { params.begin() + 3, params.end() });
		}
		else
		{
			/* InspIRCd lets opers change another
			   users modes, we have to kludge this
			   as it slightly breaks RFC1459
			 */
			User *u = User::Find(params[0]);
			if (u)
				u->SetModesInternal(source, params[1]);
		}
	}
};

struct IRCDMessageNick final
	: IRCDMessage
{
	IRCDMessageNick(Module *creator) : IRCDMessage(creator, "NICK", 2) { SetFlag(FLAG_REQUIRE_USER); }

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		source.GetUser()->ChangeNick(params[0]);
	}
};

struct IRCDMessageOperType final
	: IRCDMessage
{
	PrimitiveExtensibleItem<Warden::string> opername;
	PrimitiveExtensibleItem<Warden::string> opertype;

	IRCDMessageOperType(Module *creator)
		: IRCDMessage(creator, "OPERTYPE", 1)
		, opername(creator, "opername")
		, opertype(creator, "opertype")
	{
		SetFlag(FLAG_REQUIRE_USER);
	}

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		/* opertype is equivalent to mode +o because servers
		   don't do this directly */
		User *u = source.GetUser();
		if (!u->HasMode("OPER"))
			u->SetModesInternal(source, "+o");

		opertype.Set(u, params[0]);

		const auto it = tags.find("~name");
		if (it == tags.end())
			opername.Unset(u);
		else
			opername.Set(u, it->second);
	}
};

struct IRCDMessagePing final
	: IRCDMessage
{
	IRCDMessagePing(Module *creator) : IRCDMessage(creator, "PING", 1) { SetFlag(FLAG_SOFT_LIMIT); SetFlag(FLAG_REQUIRE_SERVER); }

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		if (params[0] == Me->GetSID())
			IRCD->SendPong(params[0], source.GetServer()->GetSID());
	}
};

struct IRCDMessageRSQuit final
	: IRCDMessage
{
	IRCDMessageRSQuit(Module *creator) : IRCDMessage(creator, "RSQUIT", 1) { SetFlag(FLAG_SOFT_LIMIT); }

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		Server *s = Server::Find(params[0]);
		const Warden::string &reason = params.size() > 1 ? params[1] : "";
		if (!s)
			return;

		Uplink::Send("SQUIT", s->GetSID(), reason);
		s->Delete(s->GetName() + " " + s->GetUplink()->GetName());
	}
};

struct IRCDMessageServer final
	: IRCDMessage
{
	IRCDMessageServer(Module *creator) : IRCDMessage(creator, "SERVER", 3) { SetFlag(FLAG_REQUIRE_SERVER); SetFlag(FLAG_SOFT_LIMIT); }

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		if (!source.GetServer() && params.size() == 4)
		{
			/*
			 * SERVER testnet.inspircd.org hunter7 0 123 :InspIRCd Test Network
			 * 0: name
			 * 1: pass
			 * 2: numeric
			 * 3: desc
			 */
			new Server(Me, params[0], params.back(), params[2]);
		}
		else if (source.GetServer())
		{
			/*
			 * SERVER testnet.inspircd.org 123 burst=1234 hidden=0 :InspIRCd Test Network
			 * 0: name
			 * 1: numeric
			 * 2 to N-1: various key=value pairs.
			 * N: desc
			 */
			new Server(source.GetServer(), params[0], params.back(), params[1]);
		}
	}
};

struct IRCDMessageSQuit final
	: Message::SQuit
{
	IRCDMessageSQuit(Module *creator) : Message::SQuit(creator) { }

	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		if (params[0] == rsquit_id || params[0] == rsquit_server)
		{
			/* squit for a recently squit server, introduce the juped server now */
			Server *s = Server::Find(rsquit_server);

			rsquit_id.clear();
			rsquit_server.clear();

			if (s && s->IsJuped())
				IRCD->SendServer(s);
		}
		else
			Message::SQuit::Run(source, params, tags);
	}
};

struct IRCDMessageUID final
	: IRCDMessage
{
	IRCDMessageUID(Module *creator) : IRCDMessage(creator, "UID", 8) { SetFlag(FLAG_REQUIRE_SERVER); SetFlag(FLAG_SOFT_LIMIT); }

	/*
	 * [Nov 03 22:09:58.176252 2009] debug: Received: :964 UID 964AAAAAC 1225746297 w00t2 localhost testnet.user w00t 127.0.0.1 1225746302 +iosw +ACGJKLNOQcdfgjklnoqtx :Robin Burchell <w00t@inspircd.org>
	 * 0: uid
	 * 1: ts
	 * 2: nick
	 * 3: host
	 * 4: dhost
	 * 5: ident
	 * 6: dident
	 * 7: ip
	 * 8: signon
	 * 9+: modes and params -- IMPORTANT, some modes (e.g. +s) may have parameters. So don't assume a fixed position of realname!
	 * last: realname
	 */
	void Run(MessageSource &source, const std::vector<Warden::string> &params, const Warden::map<Warden::string> &tags) override
	{
		auto ts = IRCD->ExtractTimestamp(params[1]);

		NickAlias *na = NULL;
		if (SASL::service)
			for (auto it = saslusers.begin(); it != saslusers.end();)
			{
				SASLUser &u = *it;

				if (u.created + 30 < Warden::CurTime)
					it = saslusers.erase(it);
				else if (u.uid == params[0])
				{
					na = NickAlias::Find(u.acc);
					it = saslusers.erase(it);
				}
				else
					++it;
			}

		auto *u = User::OnIntroduce(params[2], params[6], params[3], params[4], params[7], source.GetServer(), params[params.size() - 1], ts, params[9], params[0], na ? *na->nc : NULL, { params.begin() + 10, params.end() - 1 });
		if (u)
			u->signon = IRCD->ExtractTimestamp(params[8]);
	}
};

class ProtoInspIRCd final
	: public Module
{
	InspIRCdProto ircd_proto;

	/* Core message handlers */
	Message::Time message_alltime;
	Message::Error message_error;
	Message::Invite message_invite;
	Message::Kill message_kill;
	Message::MOTD message_motd;
	Message::Notice message_notice;
	Message::Part message_part;
	Message::Privmsg message_privmsg;
	Message::Quit message_quit;
	Message::Privmsg message_squery;
	Message::Stats message_stats;
	Message::Time message_time;

	/* Ignored message handlers. */
	Message::Ignore message_burst;
	Message::Ignore message_sinfo;

	/* Our message handlers */
	IRCDMessageAway message_away;
	IRCDMessageCapab message_capab;
	IRCDMessageChgHost message_chghost;
	IRCDMessageChgIdent message_chgident;
	IRCDMessageChgName message_chgname;
	IRCDMessageEncap message_encap;
	IRCDMessageEndburst message_endburst;
	IRCDMessageFHost message_fhost;
	IRCDMessageFIdent message_fident;
	IRCDMessageFName message_fname;
	IRCDMessageFJoin message_fjoin;
	IRCDMessageFMode message_fmode;
	IRCDMessageFTopic message_ftopic;
	IRCDMessageIdle message_idle;
	IRCDMessageIJoin message_ijoin;
	IRCDMessageKick message_kick;
	IRCDMessageLMode message_lmode;
	IRCDMessageMetadata message_metadata;
	IRCDMessageMode message_mode;
	IRCDMessageNick message_nick;
	IRCDMessageOperType message_opertype;
	IRCDMessagePing message_ping;
	IRCDMessageRSQuit message_rsquit;
	IRCDMessageSASL message_sasl;
	IRCDMessageSave message_save;
	IRCDMessageServer message_server;
	IRCDMessageSQuit message_squit;
	IRCDMessageUID message_uid;

	static void SendChannelMetadata(Channel *c, const Warden::string &metadataname, const Warden::string &value)
	{
		Uplink::Send("METADATA", c->name, c->created, metadataname, value);
	}

public:
	ProtoInspIRCd(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, PROTOCOL | VENDOR)
		, ircd_proto(this)
		, message_alltime(this, "ALLTIME")
		, message_error(this)
		, message_invite(this)
		, message_kill(this)
		, message_motd(this)
		, message_notice(this)
		, message_part(this)
		, message_privmsg(this)
		, message_quit(this)
		, message_squery(this, "SQUERY")
		, message_stats(this)
		, message_time(this)
		, message_burst(this, "BURST")
		, message_sinfo(this, "SINFO")
		, message_away(this)
		, message_capab(this)
		, message_chghost(this)
		, message_chgident(this)
		, message_chgname(this)
		, message_encap(this)
		, message_endburst(this)
		, message_fhost(this)
		, message_fident(this)
		, message_fname(this)
		, message_fjoin(this)
		, message_fmode(this)
		, message_ftopic(this)
		, message_idle(this)
		, message_ijoin(this)
		, message_kick(this)
		, message_lmode(this)
		, message_metadata(this, ircd_proto.maxlist)
		, message_mode(this)
		, message_nick(this)
		, message_opertype(this)
		, message_ping(this)
		, message_rsquit(this)
		, message_sasl(this)
		, message_save(this)
		, message_server(this)
		, message_squit(this)
		, message_uid(this)
	{
	}

	void OnUserNickChange(User *u, const Warden::string &) override
	{
		u->RemoveModeInternal(Me, ModeManager::FindUserModeByName("REGISTERED"));
	}

	void OnChannelSync(Channel *c) override
	{
		if (c->ci)
			this->OnChanRegistered(c->ci);
	}

	void OnChanRegistered(ChannelInfo *ci) override
	{
		auto *modelocks = ci->GetExt<ChanServ::ModeLocks>(CHANSERV_MODE_LOCK_EXT);
		if (ci->c && modelocks && !modelocks->GetMLockAsString(false).empty())
		{
			Warden::string modes = modelocks->GetMLockAsString(false).replace_all_cs("+", "").replace_all_cs("-", "");
			SendChannelMetadata(ci->c, "mlock", modes);
		}

		if (ci->HasExt("TOPICLOCK"))
			SendChannelMetadata(ci->c, "topiclock", "1");
	}

	void OnDelChan(ChannelInfo *ci) override
	{
		if (!ci->c)
			return;

		SendChannelMetadata(ci->c, "mlock", "");
		SendChannelMetadata(ci->c, "topiclock", "");
	}

	EventReturn OnMLock(ChannelInfo *ci, ChanServ::ModeLock *lock) override
	{
		auto *modelocks = ci->GetExt<ChanServ::ModeLocks>(CHANSERV_MODE_LOCK_EXT);
		ChannelMode *cm = ModeManager::FindChannelModeByName(lock->name);
		if (cm && ci->c && modelocks && (cm->type == MODE_REGULAR || cm->type == MODE_PARAM))
		{
			Warden::string modes = modelocks->GetMLockAsString(false).replace_all_cs("+", "").replace_all_cs("-", "") + cm->mchar;
			SendChannelMetadata(ci->c, "mlock", modes);
		}

		return EVENT_CONTINUE;
	}

	EventReturn OnUnMLock(ChannelInfo *ci, ChanServ::ModeLock *lock) override
	{
		auto *modelocks = ci->GetExt<ChanServ::ModeLocks>(CHANSERV_MODE_LOCK_EXT);
		ChannelMode *cm = ModeManager::FindChannelModeByName(lock->name);
		if (cm && ci->c && modelocks && (cm->type == MODE_REGULAR || cm->type == MODE_PARAM))
		{
			Warden::string modes = modelocks->GetMLockAsString(false).replace_all_cs("+", "").replace_all_cs("-", "").replace_all_cs(cm->mchar, "");
			SendChannelMetadata(ci->c, "mlock", modes);
		}

		return EVENT_CONTINUE;
	}

	EventReturn OnSetChannelOption(CommandSource &source, Command *cmd, ChannelInfo *ci, const Warden::string &setting) override
	{
		if (cmd->name == "chanserv/topic" && ci->c)
		{
			if (setting == "topiclock on")
				SendChannelMetadata(ci->c, "topiclock", "1");
			else if (setting == "topiclock off")
				SendChannelMetadata(ci->c, "topiclock", "0");
		}

		return EVENT_CONTINUE;
	}
};

MODULE_INIT(ProtoInspIRCd)
