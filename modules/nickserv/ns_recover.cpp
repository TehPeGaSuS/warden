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
#include "modules/nickserv/cert.h"
#include "modules/nickserv/service.h"

typedef std::map<Warden::string, ChannelStatus> NSRecoverInfo;

class NSRecoverSvsnick final
{
public:
	Reference<User> from;
	Warden::string to;
};

class NSRecoverRequest final
	: public IdentifyRequest
{
	CommandSource source;
	Command *cmd;
	Warden::string user;

	// Whether this is LOGIN rather than RECOVER.
	bool login;

	// Log the user running the command in to the account. LOGIN also switches
	// away from the account they are on now; RECOVER, and opers using LOGIN by
	// privilege alone, only log in users who are not identified yet.
	void LogInAs(NickAlias *na)
	{
		auto *su = source.GetUser();
		auto *old = su->Account();
		NickCore *nc = na ? *na->nc : nullptr;
		if (!nc || old == nc || (old && (!login || !proven)))
			return;

		if (old)
		{
			IRCD->SendLogout(su);
			su->RemoveMode(source.service, "REGISTERED");
			su->Logout();
			su->super_admin = false;
			FOREACH_MOD(OnNickLogout, (su));
		}

		// As IDENTIFY does: tells the IRCd about the login and runs the
		// identify hooks.
		su->Identify(na);

		if (old)
		{
			Log(LOG_COMMAND, source, cmd) << "and switched from " << old->display << " to " << nc->display;
			source.Reply(_("You are now logged in as \002%s\002 (was \002%s\002)."), nc->display.c_str(), old->display.c_str());
		}
		else
		{
			Log(LOG_COMMAND, source, cmd) << "and was automatically identified to " << nc->display;
			source.Reply(_("You have been logged in as \002%s\002."), nc->display.c_str());
		}
	}

public:
	// Whether the user proved they own the account (password, cert or already
	// identified to it) rather than using the nickserv/recover privilege.
	bool proven = true;

	NSRecoverRequest(Module *o, CommandSource &src, Command *c, const Warden::string &nick, const Warden::string &pass)
		: IdentifyRequest(o, nick, pass, src.ip)
		, source(src)
		, cmd(c)
		, user(nick)
		, login(c->name == "nickserv/login")
	{
	}

	void OnSuccess(NickAlias *na) override
	{
		User *u = User::Find(user, true);
		if (!source.GetUser() || !source.service)
			return;

		Log(LOG_COMMAND, source, cmd) << "for " << na->nick;

		/* LOGIN on the nick you are already using: identify, as IDENTIFY would. */
		if (login && u && u == source.GetUser())
		{
			if (u->Account() == na->nc)
				source.Reply(_("You are already identified."));
			else if (!proven && u->IsIdentified())
				source.Reply(_("You are already logged in to another account; give the password to switch."));
			else
			{
				source.Reply(_("Password accepted - you are now recognized."));
				u->Identify(na);
			}
			return;
		}

		// LOGIN by privilege alone does not switch accounts; say so instead of
		// moving an oper onto the nick while they stay on their own account.
		if (login && !proven && source.GetAccount() && source.GetAccount() != na->nc)
		{
			source.Reply(_("You are already logged in to another account; give the password to switch."));
			return;
		}

		/* Nobody is on the nick: release any hold; LOGIN also logs in and takes the nick. */
		if (!u)
		{
			if (na->HasExt("HELD"))
			{
				NickServ::service->Release(na);
				source.Reply(_("Services' hold on \002%s\002 has been released."), na->nick.c_str());
			}
			else if (!login)
				source.Reply(_("No one is using your nick, and services are not holding it."));

			if (!login)
				return;

			LogInAs(na);

			if (source.GetUser()->nick.equals_ci(na->nick))
				;
			else if (IRCD->CanSVSNick)
				IRCD->SendForceNickChange(source.GetUser(), na->nick, Warden::CurTime);
			else
				source.Reply(_("The nick \002%s\002 is free; use \002/NICK %s\002 to take it."), na->nick.c_str(), na->nick.c_str());
		}
		// If the user being recovered is identified for the account of the nick then the user is the
		// same person that is executing the command, so kill them off (old GHOST command).
		else if (u->Account() == na->nc)
		{
			LogInAs(na);

			if (Config->GetModule("ns_recover").Get<bool>("restoreonrecover"))
			{
				if (!u->chans.empty())
				{
					auto *ei = source.GetUser()->Extend<NSRecoverInfo>("recover");
					for (auto &[chan, cuc] : u->chans)
						(*ei)[chan->name] = cuc->status;
				}
			}

			u->SendMessage(source.service, _(
					"This nickname has been recovered by %s. If you did not do "
					"this then %s may have your password, and you should change it."
				),
				source.GetNick().c_str(),
				source.GetNick().c_str());

			Warden::string buf = source.command.upper() + " command used by " + source.GetNick();
			u->Kill(*source.service, buf);

			source.Reply(_("Ghost with your nick has been killed."));

			if (IRCD->CanSVSNick)
				IRCD->SendForceNickChange(source.GetUser(), GetAccount(), Warden::CurTime);
		}
		/* User is not identified or not identified to the same account as the person using this command */
		else
		{
			LogInAs(na);

			u->SendMessage(source.service, _("This nickname has been recovered by %s."), source.GetNick().c_str());

			if (IRCD->CanSVSNick)
			{
				auto *svs = u->Extend<NSRecoverSvsnick>("svsnick");
				svs->from = source.GetUser();
				svs->to = u->nick;
			}

			if (NickServ::service)
				NickServ::service->Collide(u, na);

			if (IRCD->CanSVSNick)
			{
				/* If we can svsnick then release our hold and svsnick the user using the command */
				if (NickServ::service)
					NickServ::service->Release(na);

				source.Reply(_("You have regained control of \002%s\002."), u->nick.c_str());
			}
			else
			{
				source.Reply(_("The user with your nick has been removed. Use this command again to release services's hold on your nick."));
			}
		}
	}

	void OnFail() override
	{
		if (NickAlias::Find(GetAccount()) != NULL)
		{
			source.Reply(ACCESS_DENIED);
			if (!GetPassword().empty())
			{
				Log(LOG_COMMAND, source, cmd) << "with an invalid password for " << GetAccount();
				if (source.GetUser())
					source.GetUser()->BadPassword();
			}
		}
		else
			source.Reply(NICK_X_NOT_REGISTERED, GetAccount().c_str());
	}
};

class CommandNSRecover
	: public Command
{
public:
	CommandNSRecover(Module *creator, const Warden::string &sname = "nickserv/recover") : Command(creator, sname, 1, 2)
	{
		this->SetDesc(_("Regain control of your nick"));
		this->SetSyntax(_("\037nickname\037 [\037password\037]"));
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		const Warden::string &nick = params[0];
		const Warden::string &pass = params.size() > 1 ? params[1] : "";

		User *user = User::Find(nick, true);

		if (user && source.GetUser() == user && this->name != "nickserv/login")
		{
			source.Reply(_("You can't %s yourself!"), source.command.lower().c_str());
			return;
		}

		auto *na = NickAlias::Find(nick);
		if (!na)
		{
			source.Reply(NICK_X_NOT_REGISTERED, nick.c_str());
			return;
		}
		else if (na->nc->HasExt("NS_SUSPENDED"))
		{
			source.Reply(NICK_X_SUSPENDED, na->nick.c_str());
			return;
		}

		bool ok = false;
		if (source.GetAccount() == na->nc)
			ok = true;

		auto *cl = na->nc->GetExt<NickServ::CertList>(NICKSERV_CERT_EXT);
		if (source.GetUser() && !source.GetUser()->fingerprint.empty() && cl && cl->FindCert(source.GetUser()->fingerprint))
			ok = true;

		// The privilege is for opers who give no password; with one, it is
		// checked as for anyone else, so LOGIN can switch accounts.
		bool bypriv = false;
		if (!ok && pass.empty() && source.HasPriv("nickserv/recover"))
			ok = bypriv = true;

		if (!ok && !pass.empty())
		{
			auto *req = new NSRecoverRequest(owner, source, this, na->nick, pass);
			FOREACH_MOD(OnCheckAuthentication, (source.GetUser(), req));
			req->Dispatch();
		}
		else
		{
			NSRecoverRequest req(owner, source, this, na->nick, pass);
			req.proven = !bypriv;

			if (ok)
				req.OnSuccess(na);
			else
				req.OnFail();
		}
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Recovers your nick from another user or from services. "
			"If services are currently holding your nick, the hold "
			"will be released. If another user is holding your nick "
			"and is identified they will be killed (similar to the old "
			"GHOST command). If they are not identified they will be "
			"forced off of the nick."
		));
		return true;
	}
};

// LOGIN <nick> <password>: log out of the current account, log in to the
// nick's account and take the nick, whether it is in use, held or free.
class CommandNSLogin final
	: public CommandNSRecover
{
public:
	CommandNSLogin(Module *creator) : CommandNSRecover(creator, "nickserv/login")
	{
		this->SetDesc(_("Switch to another account and take its nick"));
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Logs you in to the account that owns \037nickname\037 and "
			"changes your nick to it. If you are logged in to a different "
			"account you are logged out of it first."
			"\n\n"
			"If an identified user is on the nick they are killed, as "
			"with \002RECOVER\002; an unidentified user is forced off "
			"it. If services are holding the nick the hold is released."
			"\n\n"
			"If you are already using \037nickname\037, this works like "
			"\002IDENTIFY\002."
		));
		return true;
	}
};

class NSRecover final
	: public Module
{
	CommandNSRecover commandnsrecover;
	CommandNSLogin commandnslogin;
	PrimitiveExtensibleItem<NSRecoverInfo> recover;
	PrimitiveExtensibleItem<NSRecoverSvsnick> svsnick;

public:
	NSRecover(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, VENDOR),
		commandnsrecover(this), commandnslogin(this), recover(this, "recover"), svsnick(this, "svsnick")
	{

		if (Config->GetModule("nickserv").Get<bool>("nonicknameownership"))
			throw ModuleException(modname + " can not be used with options:nonicknameownership enabled");

	}

	void OnUserNickChange(User *u, const Warden::string &oldnick) override
	{
		if (Config->GetModule(this).Get<bool>("restoreonrecover"))
		{
			NSRecoverInfo *ei = recover.Get(u);
			BotInfo *NickServ = Config->GetClient("NickServ");

			if (ei != NULL && NickServ != NULL)
				for (auto it = ei->begin(), it_end = ei->end(); it != it_end;)
				{
					Channel *c = Channel::Find(it->first);
					const Warden::string &cname = it->first;
					++it;

					/* User might already be on the channel */
					if (u->FindChannel(c))
						this->OnJoinChannel(u, c);
					else if (IRCD->CanSVSJoin)
						IRCD->SendSVSJoin(NickServ, u, cname, "");
				}
		}

		NSRecoverSvsnick *svs = svsnick.Get(u);
		if (svs)
		{
			if (svs->from)
			{
				// svsnick from to to
				IRCD->SendForceNickChange(svs->from, svs->to, Warden::CurTime);
			}

			svsnick.Unset(u);
		}
	}

	void OnJoinChannel(User *u, Channel *c) override
	{
		if (Config->GetModule(this).Get<bool>("restoreonrecover"))
		{
			NSRecoverInfo *ei = recover.Get(u);

			if (ei != NULL)
			{
				auto it = ei->find(c->name);
				if (it != ei->end())
				{
					for (auto mode : it->second.Modes())
						c->SetMode(c->WhoSends(), mode, u->GetUID());

					ei->erase(it);
					if (ei->empty())
						recover.Unset(u);
				}
			}
		}
	}
};

MODULE_INIT(NSRecover)
