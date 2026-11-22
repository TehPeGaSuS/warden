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

#pragma once

namespace Encryption
{
	/** Base class for encryption contexts. */
	class Context
	{
	public:
		virtual ~Context() = default;

		/** Updates the encryption context with the specified data.
		 * @param str The data to update the context with.
		 */
		inline void Update(const Warden::string &str)
		{
			Update(reinterpret_cast<const unsigned char *>(str.c_str()), str.length());
		}

		/** Updates the encryption context with the specified data.
		 * @param data The data to update the context with.
		 * @param len The length of the data.
		 */
		virtual void Update(const unsigned char *data, size_t len) = 0;

		/** Finalises the encryption context and returns the digest. */
		virtual Warden::string Finalize() = 0;
	};

	/** Provider of encryption contexts. */
	class Provider
		: public Service
	{
	public:
		/** The byte size of the block cipher. */
		const size_t block_size;

		/** The byte size of the resulting digest. */
		const size_t digest_size;

		/** Creates a provider of encryption contexts.
		 * @param creator The module that created this provider.
		 * @param algorithm The name of the encryption algorithm.
		 * @param bs The byte size of the block cipher.
		 * @param ds The byte size of the resulting digest.
		 */
		Provider(Module *creator, const Warden::string &algorithm, size_t bs, size_t ds)
			: Service(creator, "Encryption::Provider", algorithm)
			, block_size(bs)
			, digest_size(ds)
		{
		}

		virtual ~Provider() = default;

		/** Checks whether a plain text value matches a hash created by this provider. */
		virtual bool Compare(const Warden::string &hash, const Warden::string &plain)
		{
			return !hash.empty() && hash.equals_cs(ToPrintable(Encrypt(plain)));
		}

		/** Called on initialising a encryption provider to check it works properly. */
		void Check(const Warden::map<Warden::string> &checks)
		{
			for (const auto &[hash, plain] : checks)
			{
				if (!Compare(hash, plain))
					throw ModuleException("BUG: unable to generate " + this->name + " hashes safely! Please report this!");
			}
			Log(LOG_DEBUG) << "The " << this->name << " encryption provider appears to be working correctly.";
		}

		/** Creates a new encryption context. */
		virtual std::unique_ptr<Context> CreateContext() = 0;

		/** Quickly encrypts the specified values and returns the digest. */
		template<typename... Args>
		Warden::string Encrypt(Args &&...args)
		{
			auto context = CreateContext();
			context->Update(std::forward<Args>(args)...);
			return context->Finalize();
		}

		/** Calculates the  RFC 2104 hash-based message authentication code for the specified data. */
		inline Warden::string HMAC(const Warden::string &key, const Warden::string &data)
		{
			if (!block_size)
				return {};

			auto keybuf = key.length() > block_size ? Encrypt(key) : key;
			keybuf.resize(block_size);

			Warden::string hmac1;
			Warden::string hmac2;
			for (size_t i = 0; i < block_size; ++i)
			{
				hmac1.push_back(static_cast<char>(keybuf[i] ^ 0x5C));
				hmac2.push_back(static_cast<char>(keybuf[i] ^ 0x36));
			}
			hmac2.append(data);
			hmac1.append(Encrypt(hmac2));

			return Encrypt(hmac1);
		}

		/** Converts a hash to its printable form. */
		virtual Warden::string ToPrintable(const Warden::string &hash)
		{
			return Warden::Hex(hash);
		}
	};

	/** Helper template for creating simple providers of encryption contexts. */
	template <typename T>
	class SimpleProvider final
		: public Provider
	{
	public:
		/** Creates a simple provider of encryption contexts.
		 * @param creator The module that created this provider.
		 * @param algorithm The name of the encryption algorithm.
		 * @param bs The byte size of the block cipher.
		 * @param ds The byte size of the resulting digest.
		 */
		SimpleProvider(Module *creator, const Warden::string &algorithm, size_t bs, size_t ds)
			: Provider(creator, algorithm, bs, ds)
		{
		}

		/** @copydoc Encryption::Provider::CreateContext. */
		std::unique_ptr<Context> CreateContext() override
		{
			return std::make_unique<T>();
		}
	};
}
