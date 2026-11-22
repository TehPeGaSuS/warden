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

/// BEGIN CMAKE
/// target_link_libraries(${SO} PRIVATE "vendored_sha1" "vendored_sha2")
/// END CMAKE

// PBKDF2 password hashes in the format of Atheme's crypto/pbkdf2v2 module
// (anope/anope#371), so networks moving from Atheme keep their passwords:
//
//   $z$<prf>$<iterations>$<salt>$<digest>                  PBKDF2-HMAC
//   $z$<prf>$<iterations>$<salt>$<serverkey>$<storedkey>   SCRAM
//
// <prf> picks the hash (SHA-1, SHA-256 or SHA-512) and whether the salt is
// stored base64-encoded; digests and keys are always base64. New hashes use
// PBKDF2-HMAC-SHA-512 with a 32-byte base64 salt, which Atheme can read too.

#include <random>

extern "C"
{
#include "sha1/sha1.h"
}
#include "sha2/sha2.h"

#include "module.h"
#include "modules/encryption.h"

namespace
{
	// One hash function, with the state copyable so HMAC pads are hashed once.
	template<typename Ctx, void (*Init)(Ctx *), void (*Upd)(Ctx *, const unsigned char *, size_t), void (*Fin)(Ctx *, unsigned char *), size_t BS, size_t DS>
	struct Hash final
	{
		static constexpr size_t block_size = BS;
		static constexpr size_t digest_size = DS;

		static Warden::string Digest(const Warden::string &data)
		{
			Ctx ctx;
			Init(&ctx);
			Upd(&ctx, reinterpret_cast<const unsigned char *>(data.data()), data.length());
			unsigned char out[DS];
			Fin(&ctx, out);
			return Warden::string(reinterpret_cast<const char *>(out), DS);
		}

		class HMAC final
		{
			Ctx inner, outer;

		public:
			HMAC(const Warden::string &key)
			{
				auto k = key.length() > BS ? Digest(key) : key;
				unsigned char ipad[BS], opad[BS];
				for (size_t i = 0; i < BS; ++i)
				{
					const unsigned char c = i < k.length() ? k[i] : 0;
					ipad[i] = c ^ 0x36;
					opad[i] = c ^ 0x5C;
				}
				Init(&inner);
				Upd(&inner, ipad, BS);
				Init(&outer);
				Upd(&outer, opad, BS);
			}

			void Sum(const unsigned char *data, size_t len, unsigned char *out) const
			{
				Ctx ctx = inner;
				Upd(&ctx, data, len);
				unsigned char tmp[DS];
				Fin(&ctx, tmp);
				ctx = outer;
				Upd(&ctx, tmp, DS);
				Fin(&ctx, out);
			}
		};

		// PBKDF2 with a derived key the size of one digest (all Atheme uses).
		static Warden::string PBKDF2(const Warden::string &password, const Warden::string &salt, unsigned iterations)
		{
			const HMAC hmac(password);
			auto block = salt;
			block.append("\x00\x00\x00\x01", 4);

			unsigned char u[DS], t[DS];
			hmac.Sum(reinterpret_cast<const unsigned char *>(block.data()), block.length(), u);
			std::copy(u, u + DS, t);
			for (unsigned i = 1; i < iterations; ++i)
			{
				hmac.Sum(u, DS, u);
				for (size_t j = 0; j < DS; ++j)
					t[j] ^= u[j];
			}
			return Warden::string(reinterpret_cast<const char *>(t), DS);
		}

		static Warden::string Mac(const Warden::string &key, const Warden::string &data)
		{
			unsigned char out[DS];
			HMAC(key).Sum(reinterpret_cast<const unsigned char *>(data.data()), data.length(), out);
			return Warden::string(reinterpret_cast<const char *>(out), DS);
		}
	};

	void sha1_init(SHA1_CTX *c) { SHA1Init(c); }
	void sha1_upd(SHA1_CTX *c, const unsigned char *d, size_t l) { SHA1Update(c, d, static_cast<uint32_t>(l)); }
	void sha1_fin(SHA1_CTX *c, unsigned char *o) { SHA1Final(o, c); }
	void sha256_upd(sha256_ctx *c, const unsigned char *d, size_t l) { sha256_update(c, d, static_cast<unsigned>(l)); }
	void sha512_upd(sha512_ctx *c, const unsigned char *d, size_t l) { sha512_update(c, d, static_cast<unsigned>(l)); }

	using SHA1 = Hash<SHA1_CTX, sha1_init, sha1_upd, sha1_fin, 64, 20>;
	using SHA256 = Hash<sha256_ctx, sha256_init, sha256_upd, sha256_final, SHA256_BLOCK_SIZE, SHA256_DIGEST_SIZE>;
	using SHA512 = Hash<sha512_ctx, sha512_init, sha512_upd, sha512_final, SHA512_BLOCK_SIZE, SHA512_DIGEST_SIZE>;

	bool SlowEquals(const Warden::string &a, const Warden::string &b)
	{
		if (a.length() != b.length())
			return false;
		unsigned char diff = 0;
		for (size_t i = 0; i < a.length(); ++i)
			diff |= static_cast<unsigned char>(a[i] ^ b[i]);
		return !diff;
	}

	template<typename H>
	bool VerifyWith(const Warden::string &password, const Warden::string &salt, unsigned iterations, bool scram, const Warden::string &stored)
	{
		const auto salted = H::PBKDF2(password, salt, iterations);
		if (!scram)
			return SlowEquals(salted, stored);

		// SCRAM keeps ServerKey = HMAC(SaltedPassword, "Server Key").
		// Passwords are not SASLprep-normalised, which only matters for
		// non-ASCII passwords.
		return SlowEquals(H::Mac(salted, "Server Key"), stored);
	}

	// Returns true if the hash was understood; valid says if the password matched.
	bool Verify(const Warden::string &hash, const Warden::string &password, bool &valid)
	{
		valid = false;
		if (hash.compare(0, 3, "$z$", 3) != 0)
			return false;

		std::vector<Warden::string> parts;
		sepstream sep(hash.substr(3), '$', true);
		for (Warden::string part; sep.GetToken(part); )
			parts.push_back(part);
		if (parts.size() != 4 && parts.size() != 5)
			return false;

		const auto prf = Warden::Convert<unsigned>(parts[0], 0);
		const auto iterations = Warden::Convert<unsigned>(parts[1], 0);
		if (!iterations || iterations > 5000000)
			return false;

		const bool scram = (prf >= 40 && prf < 50) || prf >= 60;
		const bool salt64 = (prf >= 20 && prf < 30) || prf >= 60;
		if (scram != (parts.size() == 5))
			return false;

		const auto salt = salt64 ? Warden::B64Decode(parts[2]) : parts[2];
		const auto stored = Warden::B64Decode(parts[3]);
		if (salt.empty() || password.empty())
			return true;

		switch (prf % 10)
		{
			case 4:
				valid = VerifyWith<SHA1>(password, salt, iterations, scram, stored);
				return true;
			case 5:
				valid = VerifyWith<SHA256>(password, salt, iterations, scram, stored);
				return true;
			case 6:
				valid = VerifyWith<SHA512>(password, salt, iterations, scram, stored);
				return true;
		}
		return false; // MD5 and unknown PRFs are not supported.
	}

	unsigned iterations_conf = 64000;

	Warden::string Generate(const Warden::string &password)
	{
		static std::random_device device;
		static std::mt19937 engine(device());
		std::uniform_int_distribution<int> dist(0, 255);

		Warden::string salt;
		for (size_t i = 0; i < 32; ++i)
			salt.push_back(static_cast<char>(dist(engine)));

		const auto digest = SHA512::PBKDF2(password, salt, iterations_conf);
		return "$z$26$" + Warden::ToString(iterations_conf) + "$" + Warden::B64Encode(salt) + "$" + Warden::B64Encode(digest);
	}
}

class PBKDF2Context final
	: public Encryption::Context
{
	Warden::string buffer;

public:
	void Update(const unsigned char *data, size_t len) override
	{
		buffer.append(reinterpret_cast<const char *>(data), len);
	}

	Warden::string Finalize() override
	{
		return Generate(buffer);
	}
};

class PBKDF2Provider final
	: public Encryption::Provider
{
public:
	PBKDF2Provider(Module *creator)
		: Encryption::Provider(creator, "pbkdf2", 0, 0)
	{
	}

	bool Compare(const Warden::string &hash, const Warden::string &plain) override
	{
		bool valid;
		return Verify(hash, plain, valid) && valid;
	}

	std::unique_ptr<Encryption::Context> CreateContext() override
	{
		return std::make_unique<PBKDF2Context>();
	}

	Warden::string ToPrintable(const Warden::string &hash) override
	{
		return hash;
	}
};

class EPBKDF2 final
	: public Module
{
	PBKDF2Provider provider;

public:
	EPBKDF2(const Warden::string &modname, const Warden::string &creator)
		: Module(modname, creator, ENCRYPTION)
		, provider(this)
	{
		// PBKDF2-HMAC-SHA-512, 10000 iterations, base64 salt (checked against Python hashlib).
		provider.Check({
			{ "$z$26$10000$c2FsdHNhbHRzYWx0c2FsdA==$aLDQIn3bDU2+is1Hbkr5vgWGWqXzUL+KX96GHWPGM2R/FO20Re5BpIuoSKYoRD3sEtMZd1JNGKNolcwMF5VplQ==", "password" },
		});
	}

	EventReturn OnEncrypt(const Warden::string &src, Warden::string &dest) override
	{
		dest = "pbkdf2:" + Generate(src);
		return EVENT_ALLOW;
	}

	void OnCheckAuthentication(User *, IdentifyRequest *req) override
	{
		auto *na = NickAlias::Find(req->GetAccount());
		if (!na)
			return;

		NickCore *nc = na->nc;
		if (nc->pass.compare(0, 7, "pbkdf2:", 7) != 0)
			return;

		bool valid;
		if (!Verify(nc->pass.substr(7), req->GetPassword(), valid))
		{
			Log(LOG_DEBUG) << "enc_pbkdf2: unsupported hash for " << nc->display;
			return;
		}
		if (!valid)
			return;

		// Re-hash with the primary method unless that is us with the same settings.
		if (ModuleManager::FindFirstOf(ENCRYPTION) != this || nc->pass.compare(0, 13 + Warden::ToString(iterations_conf).length(), "pbkdf2:$z$26$" + Warden::ToString(iterations_conf)) != 0)
			Warden::Encrypt(req->GetPassword(), nc->pass);
		req->Success(this, na);
	}

	void OnReload(Configuration::Conf &conf) override
	{
		auto iterations = conf.GetModule(this).Get<unsigned>("iterations", "64000");
		if (iterations < 10000 || iterations > 5000000)
		{
			Log(this) << "iterations must be between 10000 and 5000000; using 64000 instead of " << iterations << '.';
			iterations = 64000;
		}
		iterations_conf = iterations;
	}
};

MODULE_INIT(EPBKDF2)
