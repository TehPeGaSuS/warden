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
#include "modules/nickserv/service.h"
#include "modules/weblink.h"

namespace
{
	Warden::string *GetCode(NickCore *nc)
	{
		auto *code = nc->GetExt<Warden::string>("passcode");
		if (!code)
		{
			code = nc->Extend<Warden::string>("passcode");
			*code = Warden::Random(Config->GetBlock("options").Get<size_t>("codelength", "15"));
		}
		return code;
	}

	time_t GetExpiry(Module* owner)
	{
		return Config->GetModule(owner).Get<time_t>("unconfirmedexpire", "1d");
	}
}

static Mail::Template regemail("registration");
static bool SendRegmail(User *u, const NickAlias *na, BotInfo *bi, Module* owner);

class CommandNSRegister final
	: public Command
{
public:
	CommandNSRegister(Module *creator) : Command(creator, "nickserv/register", 1, 2)
	{
		this->SetDesc(_("Register a nickname"));
		if (Config->GetModule("nickserv").Get<bool>("forceemail", "yes"))
			this->SetSyntax(_("\037password\037 \037email\037"));
		else
			this->SetSyntax(_("\037password\037 \037[email]\037"));
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		User *u = source.GetUser();
		Warden::string u_nick = source.GetNick();
		Warden::string pass = params[0];
		Warden::string email = params.size() > 1 ? params[1] : "";
		const Warden::string &nsregister = Config->GetModule(this->owner).Get<const Warden::string>("registration");

		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		if (nsregister.equals_ci("disable"))
		{
			source.Reply(_("Registration is currently disabled."));
			return;
		}

		time_t nickregdelay = Config->GetModule(this->owner).Get<time_t>("nickregdelay");
		time_t reg_delay = Config->GetModule("nickserv").Get<time_t>("regdelay", "15m");
		if (u && !u->HasMode("OPER") && nickregdelay && Warden::CurTime - u->timestamp < nickregdelay)
		{
			auto waitperiod = (u->timestamp + nickregdelay) -  Warden::CurTime;
			source.Reply(_("You must wait %s before registering your nick."),
				Warden::Duration(waitperiod, source.GetAccount()).c_str());
			return;
		}

		if (NickServ::service && NickServ::service->IsGuestNick(u_nick))
		{
			source.Reply(NICK_CANNOT_BE_REGISTERED, u_nick.c_str());
			return;
		}

		if (!IRCD->IsNickValid(u_nick))
		{
			source.Reply(NICK_CANNOT_BE_REGISTERED, u_nick.c_str());
			return;
		}

		if (BotInfo::Find(u_nick, true))
		{
			source.Reply(NICK_CANNOT_BE_REGISTERED, u_nick.c_str());
			return;
		}

		if (Config->GetModule("nickserv").Get<bool>("restrictopernicks"))
		{
			for (auto *o : Oper::opers)
			{
				if (!source.IsOper() && u_nick.find_ci(o->name) != Warden::string::npos)
				{
					source.Reply(NICK_CANNOT_BE_REGISTERED, u_nick.c_str());
					return;
				}
			}
		}

		if (Config->GetModule("nickserv").Get<bool>("forceemail", "yes") && email.empty())
			this->OnSyntaxError(source, "");
		else if (u && Warden::CurTime < u->lastnickreg + reg_delay)
		{
			auto waitperiod = (unsigned long)(u->lastnickreg + reg_delay) - Warden::CurTime;
			source.Reply(_("Please wait %s before using the REGISTER command again."),
				Warden::Duration(waitperiod, source.GetAccount()).c_str());
		}
		else if (NickAlias::Find(u_nick) != NULL)
			source.Reply(NICK_ALREADY_REGISTERED, u_nick.c_str());
		else if (!email.empty() && !Mail::Validate(email))
			source.Reply(MAIL_X_INVALID, email.c_str());
		else
		{
			EventReturn MOD_RESULT;
			FOREACH_RESULT(OnPasswordValidate, MOD_RESULT, (source, nullptr, pass));
			if (MOD_RESULT == EVENT_STOP)
				return;

			Warden::string encpass;
			if (!Warden::Encrypt(pass, encpass))
			{
				source.Reply(TRY_AGAIN_LATER, source.command.nobreak().c_str());
				return;
			}

			auto *nc = new NickCore(u_nick);
			auto *na = new NickAlias(u_nick, nc);
			if (!email.empty())
				nc->email = email;
			nc->pass = encpass;

			if (u)
				na->UpdateSeen(u);

			Log(LOG_COMMAND, source, this) << "to register " << na->nick << " (email: " << (!na->nc->email.empty() ? na->nc->email : "none") << ")";

			source.Reply(_("Nickname \002%s\002 registered."), u_nick.c_str());
			if (nsregister.equals_ci("admin") || nsregister.equals_ci("code"))
			{
				nc->Extend<bool>("UNCONFIRMED");
			}
			else if (nsregister.equals_ci("mail"))
			{
				if (!email.empty())
				{
					nc->Extend<bool>("UNCONFIRMED");
					SendRegmail(NULL, na, source.service, owner);
				}
			}

			FOREACH_MOD(OnNickRegister, (source.GetUser(), na, pass));

			// The network's own welcome text, if it has one.
			const auto &regmsg = Config->GetModule(this->owner).Get<const Warden::string>("registermessage");
			if (!regmsg.empty())
				source.Reply("%s", regmsg.c_str());

			if (u)
			{
				// This notifies the user that if their registration is unconfirmed
				u->Identify(na);
				u->lastnickreg = Warden::CurTime;
			}
			else if (nc->HasExt("UNCONFIRMED"))
			{
				if (nsregister.equals_ci("admin"))
					source.Reply(CONFIRM_REGISTER_ADMIN);
				else if (nsregister.equals_ci("code"))
				{
					const auto *code = GetCode(na->nc);
					source.Reply(CONFIRM_REGISTER_CODE, source.service->GetQueryCommand("nickserv/confirm/register", *code).c_str());
				}
				else if (nsregister.equals_ci("mail"))
					source.Reply(CONFIRM_REGISTER_MAIL);
			}
		}
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		auto minpasslen = Config->GetModule("nickserv").Get<unsigned>("minpasslen", "10");
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
				"Registers your nickname in the %s database. Once "
				"your nick is registered, you can use the \002SET\002 and \002ACCESS\002 "
				"commands to configure your nick's settings as you like "
				"them. Make sure you remember the password you use when "
				"registering - you'll need it to make changes to your nick "
				"later. (Note that \002case matters!\002 \037WARDEN\037, \037Warden\037, and "
				"\037warden\037 are all different passwords!) "
				"\n\n"
				"Guidelines on choosing passwords:"
				"\n\n"
				"Passwords should not be easily guessable. For example, "
				"using your real name as a password is a bad idea. Using "
				"your nickname as a password is a much worse idea ;) and, "
				"in fact, %s will not allow it. Also, short "
				"passwords are vulnerable to trial-and-error searches, so "
				"you should choose a password at least %u characters long. "
				"Finally, the space character cannot be used in passwords."
			),
			source.service->nick.c_str(),
			source.service->nick.c_str(),
			minpasslen);

		if (!Config->GetModule("nickserv").Get<bool>("forceemail", "yes"))
		{
			source.Reply(" ");
			source.Reply(_(
				"The \037email\037 parameter is optional and will set the email address for your "
				"nick immediately. You may also wish to \002SET\033HIDE\002 it after registering "
				"if it isn't the default setting already."
			));
		}

		if (!Config->GetModule("nickserv").Get<bool>("nonicknameownership"))
		{
			source.Reply(" ");
			source.Reply(_(
				"You can associate multiple nicknames with your account. All nicknames will "
				"share the same configuration, set of memos, and channel privileges."
			));
		}

		return true;
	}
};

class CommandNSConfirmRegister final
	: public Command
{
public:
	CommandNSConfirmRegister(Module *creator)
		: Command(creator, "nickserv/confirm/register", 1, 1)
	{
		this->SetDesc(_("Confirm a previous account registration"));
		this->SetSyntax(_("\037code\037"));
		this->SetSyntax(_("@\037nickname\037"), [](auto &source) { return source.HasPriv("nickserv/confirm/register"); });
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		Warden::string code;
		NickAlias *na;
		if (params[0][0] == '@')
		{
			if (!source.HasPriv("nickserv/confirm/register"))
			{
				source.Reply(ACCESS_DENIED);
				return;
			}

			auto nick = params[0].substr(1);
			na = NickAlias::Find(nick);
			if (!na)
			{
				source.Reply(NICK_X_NOT_REGISTERED, nick.c_str());
				return;
			}
		}
		else
		{
			code = params[0];
			na = source.GetAccount()->na;
		}

		NickCore *nc = na->nc;
		if (nc->HasExt("NS_SUSPENDED"))
		{
			source.Reply(NICK_X_SUSPENDED, na->nick.c_str());
			return;
		}

		if (!nc->HasExt("UNCONFIRMED"))
		{
			source.Reply(_("There is no registration confirmation pending for %s."),
				na->nick.c_str());
			return;
		}

		if (!code.empty())
		{
			auto *passcode = nc->GetExt<Warden::string>("passcode");
			if (passcode && !code.equals_cs(*passcode))
			{
				source.Reply(_("The registration confirmation code you specified for %s is incorrect."),
					na->nick.c_str());
				return;
			}
			else if (!passcode)
			{
				source.Reply(_("The registration of %s can only be confirmed by an administrator."),
					na->nick.c_str());
				return;
			}
		}

		nc->Shrink<Warden::string>("passcode");
		nc->Shrink<bool>("UNCONFIRMED");

		FOREACH_MOD(OnNickConfirm, (source.GetUser(), nc));

		auto nonicknameownership = Config->GetModule("nickserv").Get<bool>("nonicknameownership");
		for (auto *u : nc->users)
		{
			IRCD->SendLogin(u, na);

			if (!nonicknameownership)
				continue;

			const auto &aliases = *nc->aliases;
			auto it = std::find_if(aliases.begin(), aliases.end(), [&u](const auto *na) {
				return na->nick.equals_ci(u->nick);
			});
			if (it != aliases.end())
				u->SetMode(source.service, "REGISTERED"); // nick is in the group
		}

		Log(nc == source.GetAccount() ? LOG_COMMAND : LOG_ADMIN, source, this) << "to confirm the registration of " << nc->display;
		source.Reply(_("Nick \002%s\002 has been confirmed."), na->nick.c_str());
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
				"Confirms an account registration. You have %s after registration to do this "
				"before your registration expires."
			),
			Warden::Duration(GetExpiry(owner), source.GetAccount()).c_str());

		if (source.HasPriv("nickserv/confirm/register"))
		{
			source.Reply(" ");
			source.Reply(_(
				"Additionally, Services Operators with the \037nickserv/confirm/register\037 "
				"permission can specify @\037nickname\037 instead of \037code\037 to force "
				"confirm another user's account registration."
			));
		}
		return true;
	}
};

class CommandNSResend final
	: public Command
{
public:
	CommandNSResend(Module *creator)
		: Command(creator, "nickserv/resend", 0, 1)
	{
		this->SetDesc(_("Resend registration confirmation email"));
		this->SetSyntax(_("[\037nickname\037]"), [](auto &source) { return source.HasCommand("nickserv/resend"); });
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		if (!Config->GetModule(this->owner).Get<const Warden::string>("registration").equals_ci("mail"))
		{
			source.Reply(ACCESS_DENIED);
			return;
		}

		auto is_oper = false;
		Warden::string nick;
		if (!params.empty() && source.HasCommand("nickserv/resend"))
		{
			nick = params[0];
			is_oper = true;
		}
		else if (source.nc)
			nick = source.GetAccount()->display;
		else
			nick = source.GetNick();

		const auto *na = NickAlias::Find(nick);
		if (!na)
		{
			source.Reply(NICK_X_NOT_REGISTERED, nick.c_str());
			return;
		}

		NickCore *nc = na->nc;
		if (!nc->HasExt("UNCONFIRMED"))
		{
			source.Reply(_("Nick \002%s\002 is already confirmed."), na->nick.c_str());
			return;
		}

		if (!is_oper && Warden::CurTime < nc->lastmail + Config->GetModule(this->owner).Get<time_t>("resenddelay"))
		{
			source.Reply(_("Cannot send mail now; please retry a little later."));
			return;
		}

		if (!SendRegmail(source.GetUser(), na, source.service, owner))
		{
			Log(this->owner) << "Unable to resend registration confirmation code for " << na->nick;
			return;
		}

		nc->lastmail = Warden::CurTime;
		source.Reply(_("The confirmation code for \002%s\002 has been re-sent to %s."),
			na->nick.c_str(), nc->email.c_str());

		Log(nc == source.GetAccount() ? LOG_COMMAND : LOG_ADMIN, source, this) << "to resend the registration confirmation code for " << na->nick;
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		if (!Config->GetModule(this->owner).Get<const Warden::string>("registration").equals_ci("mail"))
			return false;

		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_("This command will resend a registration confirmation email."));

		if (source.HasCommand("nickserv/resend"))
		{
			source.Reply(" ");
			source.Reply(_(
				"Additionally, Services Operators with the \037nickserv/resend\037 permission "
				"can specify a nickname to resend a confirmation email for another account."
			));
		}
		return true;
	}

	void OnServHelp(CommandSource &source, HelpWrapper &help) override
	{
		if (Config->GetModule(this->owner).Get<const Warden::string>("registration").equals_ci("mail"))
			Command::OnServHelp(source, help);
	}
};

class CommandNSSARegister final
	: public Command
{
public:
	CommandNSSARegister(Module *creator) : Command(creator, "nickserv/saregister", 2, 3)
	{
		this->SetDesc(_("Register a nickname for someone else"));
		this->SetSyntax(_("\037nickname\037 \037password\037 [\037email\037]"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		const auto &nick = params[0];
		const auto &pass = params[1];
		const auto email = params.size() > 2 ? params[2] : "";

		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		if ((NickServ::service && NickServ::service->IsGuestNick(nick)) || !IRCD->IsNickValid(nick) || BotInfo::Find(nick, true))
		{
			source.Reply(NICK_CANNOT_BE_REGISTERED, nick.c_str());
			return;
		}

		if (NickAlias::Find(nick))
		{
			source.Reply(NICK_ALREADY_REGISTERED, nick.c_str());
			return;
		}

		if (!email.empty() && !Mail::Validate(email))
		{
			source.Reply(MAIL_X_INVALID, email.c_str());
			return;
		}

		// Validated as if the new nick were registering (no user, so the
		// oper's own nick, ident and realname play no part). The oper's
		// account stays, for their language and oper-only details such as a
		// forbid's reason, and replies keep the command's msgid.
		CommandSource target(nick, nullptr, source.nc, source.reply, source.service, source.msgid);
		target.command = source.command;
		target.permission = source.permission;
		EventReturn MOD_RESULT;
		FOREACH_RESULT(OnPasswordValidate, MOD_RESULT, (target, nullptr, pass));
		if (MOD_RESULT == EVENT_STOP)
			return;

		Warden::string encpass;
		if (!Warden::Encrypt(pass, encpass))
		{
			source.Reply(TRY_AGAIN_LATER, source.command.nobreak().c_str());
			return;
		}

		// Registered by an oper, so already confirmed. Nobody is logged in to
		// it: the owner identifies with the password they were given.
		auto *nc = new NickCore(nick);
		auto *na = new NickAlias(nick, nc);
		nc->email = email;
		nc->pass = encpass;

		auto *u = User::Find(nick, true);
		if (u)
			na->UpdateSeen(u);

		Log(LOG_ADMIN, source, this) << "to register " << na->nick << " (email: " << (!email.empty() ? email : "none") << ")";
		source.Reply(_("Nickname \002%s\002 registered."), na->nick.c_str());

		FOREACH_MOD(OnNickRegister, (nullptr, na, pass));

		// Whoever is using the nick now has to identify, as with any
		// registered nick.
		if (u && NickServ::service)
			NickServ::service->Validate(u);
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Registers \037nickname\037 with the given password and email "
			"address, for someone else. The account is confirmed straight "
			"away, and nobody is logged in to it: give the owner the password "
			"so they can identify. If someone is using the nick, they are asked "
			"to identify as with any registered nick."
			"\n\n"
			"The email limit (\002maxemails\002) and forbids do not apply."
		));
		return true;
	}
};

class NSRegister final
	: public Module
{
	CommandNSRegister commandnsregister;
	CommandNSConfirmRegister commandnsconfirmregister;
	CommandNSResend commandnsresend;
	CommandNSSARegister commandnssaregister;

	SerializableExtensibleItem<bool> unconfirmed;
	SerializableExtensibleItem<Warden::string> passcode;

public:
	NSRegister(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, VENDOR)
		, commandnsregister(this)
		, commandnsconfirmregister(this)
		, commandnsresend(this)
		, commandnssaregister(this)
		, unconfirmed(this, "UNCONFIRMED")
		, passcode(this, "passcode")
	{
		if (Config->GetModule(this).Get<const Warden::string>("registration").equals_ci("disable"))
			throw ModuleException("Module " + this->name + " will not load with registration disabled.");
	}

	void OnReload(Configuration::Conf &conf) override
	{
		regemail.Reload(conf);
	}

	void OnNickIdentify(User *u) override
	{
		BotInfo *NickServ;
		if (unconfirmed.HasExt(u->Account()) && (NickServ = Config->GetClient("NickServ")))
		{
			const Warden::string &nsregister = Config->GetModule(this).Get<const Warden::string>("registration");
			if (nsregister.equals_ci("admin"))
				u->SendMessage(NickServ, CONFIRM_REGISTER_ADMIN);
			else if (nsregister.equals_ci("code"))
			{
				const auto *code = GetCode(u->Account());
				u->SendMessage(NickServ, CONFIRM_REGISTER_CODE, NickServ->GetQueryCommand("nickserv/confirm/register", *code).c_str());
			}
			else if (nsregister.equals_ci("mail"))
				u->SendMessage(NickServ, CONFIRM_REGISTER_MAIL);

			const NickAlias *this_na = u->AccountNick();
			time_t registered = Warden::CurTime - this_na->registered;
			const auto unconfirmed_expire = GetExpiry(this);
			if (unconfirmed_expire > registered)
				u->SendMessage(NickServ, _("Your account will expire, if not confirmed, in %s."), Warden::Duration(unconfirmed_expire - registered, u->Account()).c_str());
		}
	}

	void OnPreNickExpire(NickAlias *na, bool &expire) override
	{
		if (unconfirmed.HasExt(na->nc))
		{
			const auto unconfirmed_expire = GetExpiry(this);
			if (unconfirmed_expire && Warden::CurTime - na->registered >= unconfirmed_expire)
				expire = true;
		}
	}
};

static bool SendRegmail(User *u, const NickAlias *na, BotInfo *bi, Module *owner)
{
	NickCore *nc = na->nc;
	auto *code = GetCode(na->nc);

	Warden::map<Warden::string> vars = {
		{ "nick",    na->nick                                                                },
		{ "network", Config->GetBlock("networkinfo").Get<const Warden::string>("networkname") },
		{ "code",    *code                                                                   },
		{ "expiry",  Warden::Duration(GetExpiry(owner), na->nc)                               },
		{ "link",    WebLink::Create(WebLink::Type::REGISTER, na, *code, GetExpiry(owner))   },
	};

	return regemail.Send(u, nc, bi, vars);
}

MODULE_INIT(NSRegister)
