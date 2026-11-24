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
#include "modules/nickserv/resetpass.h"
#include "modules/weblink.h"
#include "modules/encryption.h"

namespace
{
	time_t GetExpiry(Module* owner)
	{
		return Config->GetModule(owner).Get<time_t>("resetexpire", "1d");
	}
}

// Recovery keys: on networks that confirm registrations with a code
// ({ns_register}:registration = "code") users get a one-time key when they
// confirm, and RESETPASS nick <key> logs them back in. Keys are only stored as
// SHA-256 hashes; bots that register and never confirm never get one.
#define RECOVERYKEY_EXT "RECOVERYKEY"
#define KEY_PREFIX "WRD-"

namespace
{
	ServiceReference<Encryption::Provider> sha256("Encryption::Provider", "sha256");

	bool CodeMode()
	{
		return Config->GetModule("ns_register").Get<const Warden::string>("registration").equals_ci("code");
	}

	Warden::string Hash(const Warden::string &key)
	{
		return sha256 ? Warden::Hex(sha256->Encrypt(key)) : "";
	}

	bool IsKey(const Warden::string &param)
	{
		return param.find_ci(KEY_PREFIX) == 0;
	}
}

class RecoveryKeys final
{
	SerializableExtensibleItem<Warden::string> &keys;

public:
	RecoveryKeys(SerializableExtensibleItem<Warden::string> &k) : keys(k) { }

	// Makes a new key for an account, replacing any old one, and returns it.
	Warden::string Create(NickCore *nc)
	{
		const auto raw = Warden::Random(25);
		Warden::string key = KEY_PREFIX;
		for (size_t i = 0; i < raw.length(); i += 5)
			key.append(i ? "-" : "").append(raw.substr(i, 5));

		keys.Set(nc, Hash(key));
		return key;
	}

	bool Check(NickCore *nc, const Warden::string &key)
	{
		auto *hash = keys.Get(nc);
		return hash && !hash->empty() && sha256 && hash->equals_cs(Hash(key));
	}

	bool Has(NickCore *nc)
	{
		return keys.HasExt(nc);
	}

	void Clear(NickCore *nc)
	{
		keys.Unset(nc);
	}

	static void Show(CommandSource &source, const NickAlias *na, const Warden::string &key)
	{
		source.Reply(_("Your recovery key is \002%s\002. Save it somewhere safe: it is shown only once."), key.c_str());
		source.Reply(_("If you forget your password, type \002%s\002 to get back into your account."),
			source.service->GetQueryCommand("nickserv/resetpass", na->nick + " " + key).c_str());
	}
};


static Mail::Template resetemail("password_reset");
static bool SendResetEmail(User *u, const NickAlias *na, BotInfo *bi, Module *owner);

class CommandNSSetRecoveryKey
	: public Command
{
protected:
	RecoveryKeys &keys;

public:
	CommandNSSetRecoveryKey(Module *creator, RecoveryKeys &k, const Warden::string &sname = "nickserv/set/recoverykey", size_t min = 0)
		: Command(creator, sname, min, min)
		, keys(k)
	{
		this->SetDesc(_("Get a new recovery key"));
		this->SetSyntax("");
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		if (Warden::ReadOnly)
		{
			source.Reply(READ_ONLY_MODE);
			return;
		}

		if (!CodeMode())
		{
			source.Reply(_("Recovery keys are not used on this network."));
			return;
		}

		NickCore *nc = source.GetAccount();
		if (!nc || nc->HasExt("UNCONFIRMED"))
		{
			source.Reply(_("Your account must be confirmed before it can have a recovery key."));
			return;
		}

		const auto key = keys.Create(nc);
		Log(LOG_COMMAND, source, this) << "to get a new recovery key";
		source.Reply(_("Your old recovery key no longer works."));
		RecoveryKeys::Show(source, nc->na, key);
	}

	void OnServHelp(CommandSource &source, HelpWrapper &help) override
	{
		// Only listed where recovery keys are used (registration = "code").
		if (CodeMode())
			Command::OnServHelp(source, help);
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Makes a new recovery key for your account and shows it to you once. The "
			"old key stops working. Use this if you lost your key or think someone "
			"else has seen it."
		));
		return true;
	}
};

class CommandNSSASetRecoveryKey final
	: public Command
{
	RecoveryKeys &keys;

public:
	CommandNSSASetRecoveryKey(Module *creator, RecoveryKeys &k)
		: Command(creator, "nickserv/saset/recoverykey", 1, 1)
		, keys(k)
	{
		this->SetDesc(_("Remove the recovery key of an account"));
		this->SetSyntax(_("\037nickname\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		auto *na = NickAlias::Find(params[0]);
		if (!na)
		{
			source.Reply(NICK_X_NOT_REGISTERED, params[0].c_str());
			return;
		}

		if (!keys.Has(na->nc))
		{
			source.Reply(_("\002%s\002 has no recovery key."), na->nc->display.c_str());
			return;
		}

		keys.Clear(na->nc);
		Log(LOG_ADMIN, source, this) << "to remove the recovery key of " << na->nc->display;
		source.Reply(_("The recovery key of \002%s\002 has been removed. Its owner can get a new one with %s."),
			na->nc->display.c_str(), source.service->GetQueryCommand("nickserv/set/recoverykey").c_str());
	}

	void OnServHelp(CommandSource &source, HelpWrapper &help) override
	{
		// Only listed where recovery keys are used (registration = "code").
		if (CodeMode())
			Command::OnServHelp(source, help);
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
			"Removes the recovery key of an account, for example if its owner thinks "
			"someone else has it. The owner can make a new one with SET RECOVERYKEY."
		));
		return true;
	}
};

using NickServ::ResetInfo;

class CommandNSResetPass final
	: public Command
{
	RecoveryKeys &keys;

	static bool UseMail()
	{
		return Config->GetBlock("mail").Get<bool>("usemail");
	}

	void ResetWithKey(CommandSource &source, NickAlias *na, const Warden::string &key)
	{
		NickCore *nc = na->nc;
		if (!keys.Check(nc, key))
		{
			Log(LOG_COMMAND, source, this) << "with an incorrect recovery key for " << na->nick << " (account: " << nc->display << ")";
			source.Reply(_("The recovery key you specified for \002%s\002 is incorrect."), na->nick.c_str());
			if (source.GetUser())
				source.GetUser()->BadPassword();
			return;
		}

		// Each key works once, and a pending email reset is no longer needed.
		const auto newkey = keys.Create(nc);
		nc->Shrink<ResetInfo>(NICKSERV_RESETPASS_EXT);

		if (source.GetUser())
			source.GetUser()->Identify(na);

		Log(LOG_COMMAND, source, this) << "to recover " << na->nick << " (account: " << nc->display << ") with its recovery key";
		source.Reply(_("You are now identified as \002%s\002. Change your password now using %s."),
			na->nick.c_str(), source.service->GetQueryCommand("nickserv/set/password").c_str());
		source.Reply(_("Your old recovery key no longer works."));
		RecoveryKeys::Show(source, na, newkey);
	}

public:
	CommandNSResetPass(Module *creator, RecoveryKeys &k)
		: Command(creator, "nickserv/resetpass", 2, 2)
		, keys(k)
	{
		this->SetDesc(_("Recover access to an account"));
		this->SetSyntax(_("\037nickname\037 \037recovery-key\037"), [](auto &) { return CodeMode(); });
		this->SetSyntax(_("\037nickname\037 \037email\037"), [](auto &) { return UseMail(); });
		this->AllowUnregistered(true);
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		const auto withkey = CodeMode() && IsKey(params[1]);
		if (!withkey && !UseMail())
		{
			if (CodeMode())
				this->OnSyntaxError(source, "");
			else
				source.Reply(_("Password reset is not available on this network."));
			return;
		}

		NickAlias *na = NickAlias::Find(params[0]);
		if (!na)
			source.Reply(NICK_X_NOT_REGISTERED, params[0].c_str());
		else if (na->nc->HasExt("NS_SUSPENDED"))
			source.Reply(NICK_X_SUSPENDED, na->nc->display.c_str());
		else if (withkey)
			ResetWithKey(source, na, params[1]);
		else if (!na->nc->email.equals_ci(params[1]))
			source.Reply(_("Incorrect email address."));
		else
		{
			if (SendResetEmail(source.GetUser(), na, source.service, owner))
			{
				Log(LOG_COMMAND, source, this) << "for " << na->nick << " (account: " << na->nc->display << ")";
				source.Reply(_("Password reset email for \002%s\002 has been sent."), na->nick.c_str());
			}
		}
	}

	bool OnHelp(CommandSource &source, const Warden::string &subcommand) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		if (CodeMode())
		{
			source.Reply(_(
				"Gets you back into your account if you forgot its password. Give the "
				"recovery key you were shown when you confirmed your registration: you will "
				"be identified, so you can set a new password, and get a new key, as each "
				"key works only once."
			));
		}
		if (UseMail())
		{
			if (CodeMode())
			{
				source.Reply(" ");
				source.Reply(_(
					"If you give the account's email address instead, a confirmation code is "
					"sent to it."
				));
			}
			else
			{
				source.Reply(_(
					"Sends a confirmation code to the nickname's email address with instructions on "
					"how to reset their password. \037email\037 must be the email address associated "
					"with the account."
				));
			}
		}
		return true;
	}
};

class CommandNSConfirmResetPass final
	: public Command
{
private:
	PrimitiveExtensibleItem<ResetInfo> &reset;

public:
	CommandNSConfirmResetPass(Module *creator, PrimitiveExtensibleItem<ResetInfo> &r)
		: Command(creator, "nickserv/confirm/resetpass", 1, 2)
		, reset(r)
	{
		this->AllowUnregistered(true);
		this->SetDesc(_("Confirm a previous password reset"));
		this->SetSyntax(_("[\037nickname\037] \037code\037"));
	}

	void Execute(CommandSource &source, const std::vector<Warden::string> &params) override
	{
		Warden::string code, nick;
		if (params.size() > 1)
		{
			nick = params[0];
			code = params[1];
		}
		else
		{
			code = params[0];
			nick = source.GetNick();
		}

		auto *na = NickAlias::Find(nick);
		if (!na)
		{
			source.Reply(NICK_X_NOT_REGISTERED, nick.c_str());
			return;
		}

		NickCore *nc = na->nc;
		if (nc->HasExt("NS_SUSPENDED"))
		{
			source.Reply(NICK_X_SUSPENDED, na->nick.c_str());
			return;
		}

		auto *ri = reset.Get(nc);
		if (!ri)
		{
			source.Reply(_("There is no password reset confirmation pending for %s."),
				na->nick.c_str());
			return;
		}
		if (!code.equals_cs(ri->code))
		{
			source.Reply(_("The password reset code you specified for %s is incorrect."),
				na->nick.c_str());
			return;
		}

		if (ri->time < Warden::CurTime - GetExpiry(owner))
		{
			reset.Unset(nc);
			source.Reply(_("The password reset request for %s has expired."),
				na->nick.c_str());
			return;
		}

		reset.Unset(nc);

		if (Config->GetModule("ns_register").Get<const Warden::string>("registration").equals_ci("mail"))
			nc->Shrink<bool>("UNCONFIRMED");

		if (source.GetUser())
			source.GetUser()->Identify(na);

		Log(LOG_COMMAND, source, this) << "to reset their password and forcibly identify as " << na->nick;
		source.Reply(_("You are now identified as %s. Change your password now using %s."),
			na->nick.c_str(), source.service->GetQueryCommand("nickserv/set/password").c_str());
	}

	bool OnHelp(CommandSource &source, const Warden::string &) override
	{
		this->SendSyntax(source);
		source.Reply(" ");
		source.Reply(_(
				"Confirms a password reset and identifies you to the specified account. You have "
				"%s after requesting a reset to do this before your request expires. Once you "
				"have done this you can set the password using %s."
			),
			Warden::Duration(GetExpiry(owner), source.GetAccount()).c_str(),
			source.service->GetQueryCommand("nickserv/set/password").c_str()
		);
		return true;
	}
};

class NSResetPass final
	: public Module
{
private:
	SerializableExtensibleItem<Warden::string> recoverykey;
	RecoveryKeys keys;
	CommandNSConfirmResetPass commandnsconfirmpassword;
	CommandNSResetPass commandnsresetpass;
	CommandNSSetRecoveryKey commandnssetrecoverykey;
	CommandNSSASetRecoveryKey commandnssasetrecoverykey;
	PrimitiveExtensibleItem<ResetInfo> reset;

public:
	NSResetPass(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, VENDOR)
		, recoverykey(this, RECOVERYKEY_EXT)
		, keys(recoverykey)
		, commandnsconfirmpassword(this, reset)
		, commandnsresetpass(this, keys)
		, commandnssetrecoverykey(this, keys)
		, commandnssasetrecoverykey(this, keys)
		, reset(this, NICKSERV_RESETPASS_EXT)
	{
		// Without mail, only recovery keys ({ns_register}:registration = "code")
		// can reset passwords.
		if (CodeMode() && !sha256)
			Log(this) << "enc_sha2 is not loaded: recovery keys cannot be made or checked until it is.";
	}

	void OnReload(Configuration::Conf &conf) override
	{
		resetemail.Reload(conf);
	}

	void OnNickConfirm(User *u, NickCore *nc) override
	{
		// Only the owner, confirming their own registration with the code,
		// sees the key; accounts confirmed by an oper can use SET RECOVERYKEY.
		if (!CodeMode() || !sha256 || !u || u->Account() != nc)
			return;

		BotInfo *NickServ = Config->GetClient("NickServ");
		if (!NickServ)
			return;

		CommandSource source(u->nick, u, nc, u, NickServ);
		RecoveryKeys::Show(source, nc->na, keys.Create(nc));
	}

	void OnPasswordChange(CommandSource &source, NickCore *nc) override
	{
		// A new password, however it was set (IRC, RPC or the web panel's own
		// reset), cancels a pending email reset and with it any reset link.
		reset.Unset(nc);
	}

	void OnNickInfo(CommandSource &source, NickAlias *na, InfoFormatter &info, bool show_hidden) override
	{
		if (show_hidden && CodeMode())
			info[_("Recovery key")] = keys.Has(na->nc) ? _("Set") : _("None");
	}
};

static bool SendResetEmail(User *u, const NickAlias *na, BotInfo *bi, Module* owner)
{
	auto *ri = na->nc->Extend<ResetInfo>(NICKSERV_RESETPASS_EXT);
	ri->code = Warden::Random(Config->GetBlock("options").Get<size_t>("codelength", "15"));
	ri->time = Warden::CurTime;

	Warden::map<Warden::string> vars = {
		{ "nick",    na->nick                                                                },
		{ "network", Config->GetBlock("networkinfo").Get<const Warden::string>("networkname") },
		{ "code",    ri->code                                                                },
		{ "expiry",  Warden::Duration(GetExpiry(owner), na->nc)                               },
		{ "link",    WebLink::Create(WebLink::Type::RESETPASS, na, ri->code, GetExpiry(owner)) },
	};

	return resetemail.Send(u, na->nc, bi, vars);
}

MODULE_INIT(NSResetPass)
