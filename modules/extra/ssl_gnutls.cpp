// Warden IRC Services <https://github.com/TehPeGaSuS/warden>
//
// Copyright (C) 2003-2026 Anope Contributors
// Copyright (C) 2026 Warden Contributors
// Copyright (C) 2014 Attila Molnar <attilamolnar@hush.com>
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
/// find_package("GnuTLS" REQUIRED)
/// target_link_libraries(${SO} PRIVATE GnuTLS::GnuTLS)
/// END CMAKE

#include "module.h"
#include "modules/ssl.h"

#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

class GnuTLSModule;
static GnuTLSModule *me;

namespace GnuTLS { class X509CertCredentials; }

class MySSLService final
	: public SSLService
{
public:
	MySSLService(Module *o, const Warden::string &n);

	/** Initialize a socket to use SSL
	 * @param s The socket
	 */
	void Init(Socket *s) override;
	void Init(Socket *s, const Warden::string &host, bool verify) override;
};

class SSLSocketIO final
	: public SocketIO
{
public:
	gnutls_session_t sess = nullptr;
	GnuTLS::X509CertCredentials *mycreds;
	/* For outgoing connections other than the uplink: the server name to send and check. */
	Warden::string host;
	bool verify = false;

	/** Constructor
	 */
	SSLSocketIO();

	/** Really receive something from the buffer
	 * @param s The socket
	 * @param buf The buf to read to
	 * @param sz How much to read
	 * @return Number of bytes received
	 */
	ssize_t Recv(Socket *s, char *buf, size_t sz) override;

	/** Write something to the socket
	 * @param s The socket
	 * @param buf The data to write
	 * @param size The length of the data
	 */
	ssize_t Send(Socket *s, const char *buf, size_t sz) override;

	/** Accept a connection from a socket
	 * @param s The socket
	 * @return The new socket
	 */
	ClientSocket *Accept(ListenSocket *s) override;

	/** Finished accepting a connection from a socket
	 * @param s The socket
	 * @return SF_ACCEPTED if accepted, SF_ACCEPTING if still in process, SF_DEAD on error
	 */
	SocketFlag FinishAccept(ClientSocket *cs) override;

	/** Connect the socket
	 * @param s THe socket
	 * @param target IP to connect to
	 * @param port to connect to
	 */
	void Connect(ConnectionSocket *s, const Warden::string &target, int port) override;

	/** Called to potentially finish a pending connection
	 * @param s The socket
	 * @return SF_CONNECTED on success, SF_CONNECTING if still pending, and SF_DEAD on error.
	 */
	SocketFlag FinishConnect(ConnectionSocket *s) override;

	/** Called when the socket is destructing
	 */
	void Destroy() override;
};

namespace GnuTLS
{
	class Init final
	{
	public:
		Init() { gnutls_global_init(); }
		~Init() { gnutls_global_deinit(); }
	};

	/** Used to create a gnutls_datum_t* from an Warden::string
	 */
	class Datum final
	{
		gnutls_datum_t datum;

	public:
		Datum(const Warden::string &dat)
		{
			datum.data = reinterpret_cast<unsigned char *>(const_cast<char *>(dat.data()));
			datum.size = static_cast<unsigned int>(dat.length());
		}

		const gnutls_datum_t *get() const { return &datum; }
	};

	class DHParams final
	{
		gnutls_dh_params_t dh_params = nullptr;

	public:
		void Import(const Warden::string &dhstr)
		{
			if (dh_params != NULL)
			{
				gnutls_dh_params_deinit(dh_params);
				dh_params = NULL;
			}

			int ret = gnutls_dh_params_init(&dh_params);
			if (ret < 0)
				throw ConfigException("Unable to initialize DH parameters");

			ret = gnutls_dh_params_import_pkcs3(dh_params, Datum(dhstr).get(), GNUTLS_X509_FMT_PEM);
			if (ret < 0)
			{
				gnutls_dh_params_deinit(dh_params);
				dh_params = NULL;
				throw ConfigException("Unable to import DH parameters");
			}
		}

		~DHParams()
		{
			if (dh_params)
				gnutls_dh_params_deinit(dh_params);
		}

		gnutls_dh_params_t get() const { return dh_params; }
	};

	class X509Key final
	{
		/** Ensure that the key is deinited in case the constructor of X509Key throws
		 */
		class RAIIKey final
		{
		public:
			gnutls_x509_privkey_t key;

			RAIIKey()
			{
				int ret = gnutls_x509_privkey_init(&key);
				if (ret < 0)
					throw ConfigException("gnutls_x509_privkey_init() failed");
			}

			~RAIIKey()
			{
				gnutls_x509_privkey_deinit(key);
			}
		} key;

	public:
		/** Import */
		X509Key(const Warden::string &keystr)
		{
			int ret = gnutls_x509_privkey_import(key.key, Datum(keystr).get(), GNUTLS_X509_FMT_PEM);
			if (ret < 0)
				throw ConfigException("Error loading private key: " + Warden::string(gnutls_strerror(ret)));
		}

		gnutls_x509_privkey_t &get() { return key.key; }
	};

	class X509CertList final
	{
		std::vector<gnutls_x509_crt_t> certs;

	public:
		/** Import */
		X509CertList(const Warden::string &certstr)
		{
			unsigned int certcount = 3;
			certs.resize(certcount);
			Datum datum(certstr);

			int ret = gnutls_x509_crt_list_import(raw(), &certcount, datum.get(), GNUTLS_X509_FMT_PEM, GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED);
			if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER)
			{
				// the buffer wasn't big enough to hold all certs but gnutls changed certcount to the number of available certs,
				// try again with a bigger buffer
				certs.resize(certcount);
				ret = gnutls_x509_crt_list_import(raw(), &certcount, datum.get(), GNUTLS_X509_FMT_PEM, GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED);
			}

			if (ret < 0)
				throw ConfigException("Unable to load certificates" + Warden::string(gnutls_strerror(ret)));

			// Resize the vector to the actual number of certs because we rely on its size being correct
			// when deallocating the certs
			certs.resize(certcount);
		}

		~X509CertList()
		{
			for (std::vector<gnutls_x509_crt_t>::iterator i = certs.begin(); i != certs.end(); ++i)
				gnutls_x509_crt_deinit(*i);
		}

		gnutls_x509_crt_t *raw() { return &certs[0]; }
		unsigned int size() const { return certs.size(); }
	};

	class X509CertCredentials final
	{
		unsigned int refcount = 0;
		gnutls_certificate_credentials_t cred;
		DHParams dh;

		static Warden::string LoadFile(const Warden::string &filename)
		{
			std::ifstream ifs(filename.c_str());
			const Warden::string ret((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
			return ret;
		}

		static int cert_callback(gnutls_session_t sess, const gnutls_datum_t *req_ca_rdn, int nreqs, const gnutls_pk_algorithm_t *sign_algos, int sign_algos_length, gnutls_retr2_st *st);

	public:
		X509CertList certs;
		X509Key key;

		X509CertCredentials(const Warden::string &certfile, const Warden::string &keyfile)
			: certs(LoadFile(certfile)), key(LoadFile(keyfile))
		{
			if (gnutls_certificate_allocate_credentials(&cred) < 0)
				throw ConfigException("Cannot allocate certificate credentials");

			int ret = gnutls_certificate_set_x509_key(cred, certs.raw(), certs.size(), key.get());
			if (ret < 0)
			{
				gnutls_certificate_free_credentials(cred);
				throw ConfigException("Unable to set cert/key pair");
			}

			gnutls_certificate_set_retrieve_function(cred, cert_callback);
			// Only used by connections that ask for verification (e.g. SMTP).
			gnutls_certificate_set_x509_system_trust(cred);
		}

		~X509CertCredentials()
		{
			gnutls_certificate_free_credentials(cred);
		}

		void SetupSession(gnutls_session_t sess)
		{
			gnutls_credentials_set(sess, GNUTLS_CRD_CERTIFICATE, cred);
			gnutls_set_default_priority(sess);
		}

		void SetDH(const Warden::string &dhfile)
		{
			const Warden::string dhdata = LoadFile(dhfile);
			dh.Import(dhdata);
			gnutls_certificate_set_dh_params(cred, dh.get());
		}

		bool HasDH() const
		{
			return (dh.get() != NULL);
		}

		void incrref() { refcount++; }
		void decrref() { if (!--refcount) delete this; }
	};
}

class GnuTLSModule final
	: public Module
{
	GnuTLS::Init libinit;

public:
	GnuTLS::X509CertCredentials *cred = nullptr;
	MySSLService service;

	GnuTLSModule(const Warden::string &modname, const Warden::string &creator) : Module(modname, creator, EXTRA | VENDOR), service(this, "ssl")
	{
		me = this;
		this->SetPermanent(true);

		Log(this) << "Module was compiled against GnuTLS version " << GNUTLS_VERSION << " and is running against version " << gnutls_check_version(nullptr);
	}

	~GnuTLSModule()
	{
		for (std::map<int, Socket *>::const_iterator it = SocketEngine::Sockets.begin(), it_end = SocketEngine::Sockets.end(); it != it_end;)
		{
			Socket *s = it->second;
			++it;

			if (dynamic_cast<SSLSocketIO *>(s->io))
				delete s;
		}

		if (cred)
			cred->decrref();
	}

	static void CheckFile(const Warden::string &filename)
	{
		if (!Warden::IsFile(filename))
		{
			Log() << "File does not exist: " << filename;
			throw ConfigException("Error loading certificate/private key");
		}
	}

	void OnReload(Configuration::Conf &conf) override
	{
		const auto &config = conf.GetModule(this);

		const Warden::string certfile = Warden::ExpandConfig(config.Get<const Warden::string>("cert", "fullchain.pem"));
		const Warden::string keyfile = Warden::ExpandConfig(config.Get<const Warden::string>("key", "privkey.pem"));
		const Warden::string dhfile = Warden::ExpandConfig(config.Get<const Warden::string>("dh", "dhparams.pem"));

		CheckFile(certfile);
		CheckFile(keyfile);

		GnuTLS::X509CertCredentials *newcred = new GnuTLS::X509CertCredentials(certfile, keyfile);

		// DH params is not mandatory
		if (Warden::IsFile(dhfile))
		{
			try
			{
				newcred->SetDH(dhfile);
			}
			catch (...)
			{
				delete newcred;
				throw;
			}
			Log(LOG_DEBUG) << "ssl_gnutls: Successfully loaded DH parameters from " << dhfile;
		}

		if (cred)
			cred->decrref();
		cred = newcred;
		cred->incrref();

		Log(LOG_DEBUG) << "ssl_gnutls: Successfully loaded certificate " << certfile << " and private key " << keyfile;
	}

	void OnPreServerConnect() override
	{
		const auto &config = Config->GetBlock("uplink", Warden::CurrentUplink);

		if (config.Get<bool>("ssl"))
		{
			this->service.Init(UplinkSock);
		}
	}
};

/* Checks the uplink's public key against uplink:spkifp, if set (anope/anope#370).
 * Returns an error message, or an empty string if the link may go ahead.
 */
static Warden::string CheckUplinkSPKI(Socket *s, const Warden::string &actual)
{
	if (s != UplinkSock)
		return "";

	const auto &pins = Config->GetBlock("uplink", Warden::CurrentUplink).Get<const Warden::string>("spkifp");
	if (pins.empty())
		return "";

	if (actual.empty())
		return "Unable to read the uplink's public key to check uplink:spkifp";

	spacesepstream sep(pins);
	for (Warden::string pin; sep.GetToken(pin); )
	{
		if (pin == actual)
		{
			Log(LOG_DEBUG) << "Uplink public key matches uplink:spkifp (" << actual << ")";
			return "";
		}
	}

	return "The uplink's public key fingerprint " + actual + " does not match uplink:spkifp; refusing to link";
}

// Base64 of the SHA-256 of the peer certificate's SubjectPublicKeyInfo, the
// same format as UnrealIRCd's spkifp.
static Warden::string GetPeerSPKIFP(gnutls_session_t sess)
{
	unsigned int count = 0;
	const gnutls_datum_t *certs = gnutls_certificate_get_peers(sess, &count);
	if (!certs || !count)
		return "";

	gnutls_pubkey_t key;
	if (gnutls_pubkey_init(&key) < 0)
		return "";

	Warden::string result;
	gnutls_datum_t der = { nullptr, 0 };
	if (gnutls_pubkey_import_x509_raw(key, &certs[0], GNUTLS_X509_FMT_DER, 0) >= 0
		&& gnutls_pubkey_export2(key, GNUTLS_X509_FMT_DER, &der) >= 0)
	{
		unsigned char md[32];
		if (gnutls_hash_fast(GNUTLS_DIG_SHA256, der.data, der.size, md) >= 0)
			result = Warden::B64Encode(Warden::string(reinterpret_cast<const char *>(md), sizeof(md)));
		gnutls_free(der.data);
	}
	gnutls_pubkey_deinit(key);
	return result;
}

MySSLService::MySSLService(Module *o, const Warden::string &n) : SSLService(o, n)
{
}

void MySSLService::Init(Socket *s)
{
	if (s->io != &NormalSocketIO)
		throw CoreException("Socket initializing SSL twice");

	s->io = new SSLSocketIO();
}

void MySSLService::Init(Socket *s, const Warden::string &host, bool verify)
{
	this->Init(s);
	auto *io = warden_dynamic_static_cast<SSLSocketIO *>(s->io);
	io->host = host;
	io->verify = verify;
}

ssize_t SSLSocketIO::Recv(Socket *s, char *buf, size_t sz)
{
	ssize_t ret = gnutls_record_recv(this->sess, buf, sz);

	if (ret > 0)
		TotalRead += ret;
	else if (ret < 0)
	{
		switch (ret)
		{
			case GNUTLS_E_AGAIN:
			case GNUTLS_E_INTERRUPTED:
				SocketEngine::SetLastError(EAGAIN);
				break;
			default:
				if (s == UplinkSock)
				{
					// Log and fake an errno because this is a fatal error on the uplink socket
					Log() << "SSL error: " << gnutls_strerror(ret);
				}
				SocketEngine::SetLastError(ECONNRESET);
		}
	}

	return ret;
}

ssize_t SSLSocketIO::Send(Socket *s, const char *buf, size_t sz)
{
	ssize_t ret = gnutls_record_send(this->sess, buf, sz);

	if (ret > 0)
		TotalWritten += ret;
	else
	{
		switch (ret)
		{
			case 0:
			case GNUTLS_E_AGAIN:
			case GNUTLS_E_INTERRUPTED:
				SocketEngine::SetLastError(EAGAIN);
				break;
			default:
				if (s == UplinkSock)
				{
					// Log and fake an errno because this is a fatal error on the uplink socket
					Log() << "SSL error: " << gnutls_strerror(ret);
				}
				SocketEngine::SetLastError(ECONNRESET);
		}
	}

	return ret;
}

ClientSocket *SSLSocketIO::Accept(ListenSocket *s)
{
	if (s->io == &NormalSocketIO)
		throw SocketException("Attempting to accept on uninitialized socket with SSL");

	sockaddrs conaddr;

	socklen_t size = sizeof(conaddr);
	int newsock = accept(s->GetFD(), &conaddr.sa, &size);

#ifndef INVALID_SOCKET
	const int INVALID_SOCKET = -1;
#endif

	if (newsock < 0 || newsock == INVALID_SOCKET)
		throw SocketException("Unable to accept connection: " + Warden::LastError());

	ClientSocket *newsocket = s->OnAccept(newsock, conaddr);
	me->service.Init(newsocket);
	SSLSocketIO *io = warden_dynamic_static_cast<SSLSocketIO *>(newsocket->io);

	if (gnutls_init(&io->sess, GNUTLS_SERVER) != GNUTLS_E_SUCCESS)
		throw SocketException("Unable to initialize SSL socket");

	me->cred->SetupSession(io->sess);
	gnutls_transport_set_ptr(io->sess, reinterpret_cast<gnutls_transport_ptr_t>(newsock));

	newsocket->flags[SF_ACCEPTING] = true;
	this->FinishAccept(newsocket);

	return newsocket;
}

SocketFlag SSLSocketIO::FinishAccept(ClientSocket *cs)
{
	if (cs->io == &NormalSocketIO)
		throw SocketException("Attempting to finish connect uninitialized socket with SSL");
	else if (cs->flags[SF_ACCEPTED])
		return SF_ACCEPTED;
	else if (!cs->flags[SF_ACCEPTING])
		throw SocketException("SSLSocketIO::FinishAccept called for a socket not accepted nor accepting?");

	SSLSocketIO *io = warden_dynamic_static_cast<SSLSocketIO *>(cs->io);

	int ret = gnutls_handshake(io->sess);
	if (ret < 0)
	{
		if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
		{
			// gnutls_handshake() wants to read or write again;
			// if gnutls_record_get_direction() returns 0 it wants to read, otherwise it wants to write.
			if (gnutls_record_get_direction(io->sess) == 0)
			{
				SocketEngine::Change(cs, false, SF_WRITABLE);
				SocketEngine::Change(cs, true, SF_READABLE);
			}
			else
			{
				SocketEngine::Change(cs, true, SF_WRITABLE);
				SocketEngine::Change(cs, false, SF_READABLE);
			}
			return SF_ACCEPTING;
		}
		else
		{
			cs->OnError(Warden::string(gnutls_strerror(ret)));
			cs->flags[SF_DEAD] = true;
			cs->flags[SF_ACCEPTING] = false;
			return SF_DEAD;
		}
	}
	else
	{
		cs->flags[SF_ACCEPTED] = true;
		cs->flags[SF_ACCEPTING] = false;
		SocketEngine::Change(cs, false, SF_WRITABLE);
		SocketEngine::Change(cs, true, SF_READABLE);
		cs->OnAccept();
		return SF_ACCEPTED;
	}
}

void SSLSocketIO::Connect(ConnectionSocket *s, const Warden::string &target, int port)
{
	if (s->io == &NormalSocketIO)
		throw SocketException("Attempting to connect uninitialized socket with SSL");

	s->flags[SF_CONNECTING] = s->flags[SF_CONNECTED] = false;

	s->conaddr.pton(s->GetFamily(), target, port);
	int c = connect(s->GetFD(), &s->conaddr.sa, s->conaddr.size());
	if (c == -1)
	{
		if (Warden::LastErrorCode() != EINPROGRESS)
		{
			s->OnError(Warden::LastError());
			s->flags[SF_DEAD] = true;
			return;
		}
		else
		{
			SocketEngine::Change(s, true, SF_WRITABLE);
			s->flags[SF_CONNECTING] = true;
			return;
		}
	}
	else
	{
		s->flags[SF_CONNECTING] = true;
		this->FinishConnect(s);
	}
}

SocketFlag SSLSocketIO::FinishConnect(ConnectionSocket *s)
{
	if (s->io == &NormalSocketIO)
		throw SocketException("Attempting to finish connect uninitialized socket with SSL");
	else if (s->flags[SF_CONNECTED])
		return SF_CONNECTED;
	else if (!s->flags[SF_CONNECTING])
		throw SocketException("SSLSocketIO::FinishConnect called for a socket not connected nor connecting?");

	SSLSocketIO *io = warden_dynamic_static_cast<SSLSocketIO *>(s->io);

	if (io->sess == NULL)
	{
		if (gnutls_init(&io->sess, GNUTLS_CLIENT) != GNUTLS_E_SUCCESS)
			throw SocketException("Unable to initialize SSL socket");
		me->cred->SetupSession(io->sess);
		gnutls_transport_set_ptr(io->sess, reinterpret_cast<gnutls_transport_ptr_t>(s->GetFD()));

		if (!io->host.empty())
		{
			gnutls_server_name_set(io->sess, GNUTLS_NAME_DNS, io->host.c_str(), io->host.length());
			if (io->verify)
				gnutls_session_set_verify_cert(io->sess, io->host.c_str(), 0);
		}
	}

	int ret = gnutls_handshake(io->sess);
	if (ret < 0)
	{
		if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
		{
			// gnutls_handshake() wants to read or write again;
			// if gnutls_record_get_direction() returns 0 it wants to read, otherwise it wants to write.
			if (gnutls_record_get_direction(io->sess) == 0)
			{
				SocketEngine::Change(s, false, SF_WRITABLE);
				SocketEngine::Change(s, true, SF_READABLE);
			}
			else
			{
				SocketEngine::Change(s, true, SF_WRITABLE);
				SocketEngine::Change(s, false, SF_READABLE);
			}

			return SF_CONNECTING;
		}
		else
		{
			Warden::string error = gnutls_strerror(ret);
			if (ret == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR)
			{
				gnutls_datum_t out;
				const auto status = gnutls_session_get_verify_cert_status(io->sess);
				if (gnutls_certificate_verification_status_print(status, GNUTLS_CRT_X509, &out, 0) == GNUTLS_E_SUCCESS)
				{
					error = "certificate check failed: " + Warden::string(reinterpret_cast<const char *>(out.data), out.size).trim();
					gnutls_free(out.data);
				}
			}
			s->OnError(error);
			s->flags[SF_CONNECTING] = false;
			s->flags[SF_DEAD] = true;
			return SF_DEAD;
		}
	}
	else
	{
		const auto spkierr = CheckUplinkSPKI(s, GetPeerSPKIFP(io->sess));
		if (!spkierr.empty())
		{
			s->OnError(spkierr);
			s->flags[SF_CONNECTING] = false;
			s->flags[SF_DEAD] = true;
			return SF_DEAD;
		}

		s->flags[SF_CONNECTING] = false;
		s->flags[SF_CONNECTED] = true;
		SocketEngine::Change(s, false, SF_WRITABLE);
		SocketEngine::Change(s, true, SF_READABLE);
		s->OnConnect();
		return SF_CONNECTED;
	}
}

void SSLSocketIO::Destroy()
{
	if (this->sess)
	{
		gnutls_bye(this->sess, GNUTLS_SHUT_WR);
		gnutls_deinit(this->sess);
	}

	mycreds->decrref();

	delete this;
}

SSLSocketIO::SSLSocketIO() : mycreds(me->cred)
{
	mycreds->incrref();
}

int GnuTLS::X509CertCredentials::cert_callback(gnutls_session_t sess, const gnutls_datum_t *req_ca_rdn, int nreqs, const gnutls_pk_algorithm_t *sign_algos, int sign_algos_length, gnutls_retr2_st *st)
{
	st->cert_type = GNUTLS_CRT_X509;
	st->key_type = GNUTLS_PRIVKEY_X509;
	st->ncerts = me->cred->certs.size();
	st->cert.x509 = me->cred->certs.raw();
	st->key.x509 = me->cred->key.get();
	st->deinit_all = 0;

	return 0;
}

MODULE_INIT(GnuTLSModule)
