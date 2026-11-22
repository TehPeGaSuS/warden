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

/// BEGIN CMAKE
/// target_link_libraries(${SO} PRIVATE "vendored_md5")
/// END CMAKE

#include "module.h"
#include "modules/encryption.h"

extern "C"
{
#include "md5/md5.h"
}

class MD5Context final
	: public Encryption::Context
{
private:
	MD5_CTX context;

public:
	MD5Context()
	{
		MD5_Init(&context);
	}

	void Update(const unsigned char *input, size_t len) override
	{
		MD5_Update(&context, input, len);
	}

	Warden::string Finalize() override
	{
		unsigned char digest[16];
		MD5_Final(digest, &context);
		return Warden::string(reinterpret_cast<const char *>(&digest), sizeof(digest));
	}
};

class EMD5 final
	: public Module
{
private:
	Encryption::SimpleProvider<MD5Context> md5provider;

public:
	EMD5(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, DEPRECATED | ENCRYPTION | VENDOR)
		, md5provider(this, "md5", 16, 64)
	{
		if (ModuleManager::FindFirstOf(ENCRYPTION) == this)
			throw ModuleException("enc_md5 is deprecated and can not be used as a primary encryption method");

		md5provider.Check({
			{ "d41d8cd98f00b204e9800998ecf8427e", "" },
			{ "9e107d9d372bb6826bd81d3542a419d6", "The quick brown fox jumps over the lazy dog" },
		});
	}

	void OnCheckAuthentication(User *, IdentifyRequest *req) override
	{
		auto *na = NickAlias::Find(req->GetAccount());
		if (!na)
			return;

		NickCore *nc = na->nc;
		auto pos = nc->pass.find(':');
		if (pos == Warden::string::npos)
			return;

		Warden::string hash_method(nc->pass.begin(), nc->pass.begin() + pos);
		if (!hash_method.equals_cs("md5"))
			return;

		auto enc = "md5:" + Warden::Hex(md5provider.Encrypt(req->GetPassword()));
		if (nc->pass.equals_cs(enc))
		{
			// If we are NOT the first encryption module we want to re-encrypt
			// the password with the primary encryption method.
			if (ModuleManager::FindFirstOf(ENCRYPTION) != this)
				Warden::Encrypt(req->GetPassword(), nc->pass);
			req->Success(this, na);
		}
	}
};

MODULE_INIT(EMD5)
