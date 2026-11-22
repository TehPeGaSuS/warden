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

#include "services.h"
#include "timers.h"
#include "config.h"
#include "bots.h"
#include "socketengine.h"
#include "uplink.h"

#ifndef _WIN32
#include <climits>
#else
#include <process.h>
#endif

/* Command-line options: */
unsigned Warden::Debug = 0;
bool Warden::ReadOnly = false, Warden::NoFork = false, Warden::NoThird = false, Warden::NoDB = false, Warden::NoPID = false, Warden::NoExpire = false, Warden::ProtocolDebug = false;
Warden::string Warden::ServicesDir;
Warden::string Warden::ServicesBin;

int Warden::ReturnValue = 0;
sig_atomic_t Warden::Signal = 0;
bool Warden::Quitting = false;
bool Warden::Restarting = false;
Warden::string Warden::QuitReason;

static Warden::string BinaryDir;       /* Full path to services bin directory */

time_t Warden::StartTime = 0;
time_t Warden::CurTime = 0;
long long Warden::CurTimeNs = 0;

size_t Warden::CurrentUplink = -1;

class UpdateTimer final
	: public Timer
{
public:
	UpdateTimer(time_t timeout)
		: Timer(timeout)
	{
	}

	bool Tick() override
	{
		Warden::SaveDatabases();
		return true;
	}
};

class ExpireTimer final
	: public Timer
{
public:
	ExpireTimer(time_t timeout)
		: Timer(timeout)
	{
	}

	bool Tick() override
	{
		FOREACH_MOD(OnExpireTick, ());
		return true;
	}
};

void Warden::SaveDatabases()
{
	if (Warden::ReadOnly)
		return;

	Log(LOG_DEBUG) << "Saving databases";
	FOREACH_MOD(OnSaveDatabase, ());
}

/** The following comes from InspIRCd to get the full path of the Warden executable
 */
static Warden::string GetFullProgDir(const Warden::string &argv0)
{
#ifdef _WIN32
	/* Windows has specific API calls to get the EXE path that never fail.
	 * For once, Windows has something of use, compared to the POSIX code
	 * for this, this is positively neato.
	 */
	char buffer[MAX_PATH];
	if (GetModuleFileName(NULL, buffer, MAX_PATH))
	{
		Warden::string fullpath = buffer;
		Warden::string::size_type n = fullpath.rfind("\\");
		Warden::ServicesBin = fullpath.substr(n + 1, fullpath.length());
		return fullpath.substr(0, n);
	}
#else
	// Get the current working directory
	char buffer[PATH_MAX];
	if (getcwd(buffer, PATH_MAX))
	{
		Warden::string remainder = argv0;

		Warden::ServicesBin = remainder;
		Warden::string::size_type n = Warden::ServicesBin.rfind("/");
		Warden::string fullpath;
		if (Warden::ServicesBin[0] == '/')
			fullpath = Warden::ServicesBin.substr(0, n);
		else
			fullpath = Warden::string(buffer) + "/" + Warden::ServicesBin.substr(0, n);
		Warden::ServicesBin = Warden::ServicesBin.substr(n + 1, remainder.length());
		return fullpath;
	}
#endif
	return "/";
}

/* Main routine.  (What does it look like? :-) ) */

int main(int ac, char **av, char **envp)
{
	/* String comparisons won't work until we build the case map cache, so do it first */
	Warden::CaseMapRebuild();

	BinaryDir = GetFullProgDir(av[0]);
	if (BinaryDir[BinaryDir.length() - 1] == '.')
		BinaryDir = BinaryDir.substr(0, BinaryDir.length() - 2);

#ifdef _WIN32
	Warden::string::size_type n = BinaryDir.rfind('\\');
#else
	Warden::string::size_type n = BinaryDir.rfind('/');
#endif
	Warden::ServicesDir = BinaryDir.substr(0, n);

#ifdef _WIN32
	/* Clean out the module runtime directory prior to running, just in case files were left behind during a previous run */
	ModuleManager::CleanupRuntimeDirectory();

	OnStartup();
#endif

	try
	{
		/* General initialization first */
		if (!Warden::Init(ac, av))
			return Warden::ReturnValue;
	}
	catch (const CoreException &ex)
	{
		Log(LOG_TERMINAL) << "Error: " << ex.GetReason();
		return EXIT_FAILURE;
	}

	try
	{
		Uplink::Connect();
	}
	catch (const SocketException &ex)
	{
		Log(LOG_TERMINAL) << "Unable to connect to uplink #" << (Warden::CurrentUplink + 1) << " (" << Config->Uplinks[Warden::CurrentUplink].str() << "): " << ex.GetReason();
	}

	/* Set up timers */
	time_t last_check = Warden::CurTime;
	UpdateTimer updateTimer(Config->GetBlock("options").Get<time_t>("updatetimeout", "2m"));
	ExpireTimer expireTimer(Config->GetBlock("options").Get<time_t>("expiretimeout", "30m"));

	/*** Main loop. ***/
	while (!Warden::Quitting)
	{
		Log(LOG_DEBUG_2) << "Top of main loop";

		/* Process timers */
		if (Warden::CurTime - last_check >= Config->TimeoutCheck)
		{
			TimerManager::TickTimers();
			last_check = Warden::CurTime;
		}

		/* Process the socket engine */
		SocketEngine::Process();

		if (Warden::Signal)
			Warden::HandleSignal();
	}

	if (Warden::Restarting)
	{
		FOREACH_MOD(OnRestart, ());
	}
	else
	{
		FOREACH_MOD(OnShutdown, ());
	}

	if (Warden::QuitReason.empty())
		Warden::QuitReason = "Terminating, reason unknown";
	Log() << Warden::QuitReason;

	delete UplinkSock;

	ModuleManager::UnloadAll();
	SocketEngine::Shutdown();
	for (Module *m; (m = ModuleManager::FindFirstOf(PROTOCOL)) != NULL;)
		ModuleManager::UnloadModule(m, NULL);

#ifdef _WIN32
	ModuleManager::CleanupRuntimeDirectory();

	OnShutdown();
#endif

	if (Warden::Restarting)
	{
		auto pidfile = Warden::ExpandData(Config->GetBlock("serverinfo").Get<const Warden::string>("pid"));
		if (!pidfile.empty())
			remove(pidfile.c_str());

		if (chdir(BinaryDir.c_str()) == 0)
		{
			Warden::string sbin = "./" + Warden::ServicesBin;
			av[0] = const_cast<char *>(sbin.c_str());
			execve(Warden::ServicesBin.c_str(), av, envp);
		}
		Log() << "Restart failed: " << strerror(errno);
		Warden::ReturnValue = -1;
	}

	return Warden::ReturnValue;
}
