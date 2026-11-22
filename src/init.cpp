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
#include "config.h"
#include "users.h"
#include "protocol.h"
#include "bots.h"
#include "xline.h"
#include "socketengine.h"
#include "servers.h"
#include "language.h"

#ifndef _WIN32
#include <sys/wait.h>
#include <sys/stat.h>

#include <cerrno>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#endif

#include <iostream>
#include <thread>

Warden::string Warden::ConfigDir = DEFAULT_CONF_DIR;
Warden::string Warden::DataDir = DEFAULT_DATA_DIR;
Warden::string Warden::LocaleDir = DEFAULT_LOCALE_DIR;
Warden::string Warden::LogDir = DEFAULT_LOG_DIR;
Warden::string Warden::ModuleDir = DEFAULT_MODULE_DIR;

/* Vector of pairs of command line arguments and their params */
static std::vector<std::pair<Warden::string, Warden::string> > CommandLineArguments;

/** Called on startup to organize our starting arguments in a better way
 * and check for errors
 * @param ac number of args
 * @param av args
 */
static void ParseCommandLineArguments(int ac, char **av)
{
	for (int i = 1; i < ac; ++i)
	{
		Warden::string option = av[i];
		Warden::string param;
		while (!option.empty() && option[0] == '-')
			option.erase(option.begin());
		size_t t = option.find('=');
		if (t != Warden::string::npos)
		{
			param = option.substr(t + 1);
			option.erase(t);
		}

		if (option.empty())
			continue;

		CommandLineArguments.emplace_back(option, param);
	}
}

/** Check if an argument was given on startup and its parameter
 * @param name The argument name
 * @param shortname A shorter name, eg --debug and -d
 * @param param A string to put the param, if any, of the argument
 * @return true if name/shortname was found, false if not
 */
static bool GetCommandLineArgument(const Warden::string &name, char shortname, Warden::string &param)
{
	param.clear();

	for (const auto &[argument, value] : CommandLineArguments)
	{
		if (argument.equals_ci(name) || (argument.length() == 1 && argument[0] == shortname))
		{
			param = value;
			return true;
		}
	}

	return false;
}

/** Check if an argument was given on startup
 * @param name The argument name
 * @param shortname A shorter name, eg --debug and -d
 * @return true if name/shortname was found, false if not
 */
static bool GetCommandLineArgument(const Warden::string &name, char shortname = 0)
{
	Warden::string Unused;
	return GetCommandLineArgument(name, shortname, Unused);
}

bool Warden::AtTerm()
{
	return isatty(fileno(stdout)) && isatty(fileno(stdin)) && isatty(fileno(stderr));
}

static void setuidgid();

void Warden::Fork()
{
#ifndef _WIN32
	kill(getppid(), SIGUSR2);

	if (!freopen("/dev/null", "r", stdin))
		Log() << "Unable to redirect stdin to /dev/null: " << Warden::LastError();
	if (!freopen("/dev/null", "w", stdout))
		Log() << "Unable to redirect stdout to /dev/null: " << Warden::LastError();
	if (!freopen("/dev/null", "w", stderr))
		Log() << "Unable to redirect stderr to /dev/null: " << Warden::LastError();

	setpgid(0, 0);

	setuidgid();
#else
	FreeConsole();
#endif
}

void Warden::HandleSignal()
{
	switch (Signal)
	{
		case SIGHUP:
		{
			Warden::SaveDatabases();

			try
			{
				auto *new_config = new Configuration::Conf();
				Configuration::Conf *old = Config;
				Config = new_config;
				Config->Post(old);
				delete old;
			}
			catch (const ConfigException &ex)
			{
				Log() << "Error reloading configuration file: " << ex.GetReason();
			}
			break;
		}
		case SIGTERM:
		case SIGINT:
#ifndef _WIN32
			Log() << "Received " << strsignal(Signal) << " signal (" << Signal << "), exiting.";
			Warden::QuitReason = Warden::string("Services terminating via signal ") + strsignal(Signal) + " (" + Warden::ToString(Signal) + ")";
#else
			Log() << "Received signal " << Signal << ", exiting.";
			Warden::QuitReason = Warden::string("Services terminating via signal ") + Warden::ToString(Signal);
#endif
			Warden::Quitting = true;
			Warden::SaveDatabases();
			break;
#ifndef _WIN32
		case SIGUSR1:
			Warden::SaveDatabases();
			break;
#endif
	}

	Signal = 0;
}

#ifndef _WIN32
static void parent_signal_handler(int signal)
{
	if (signal == SIGUSR2)
	{
		Warden::Quitting = true;
	}
	else if (signal == SIGCHLD)
	{
		Warden::ReturnValue = -1;
		Warden::Quitting = true;
		int status = 0;
		wait(&status);
		if (WIFEXITED(status))
			Warden::ReturnValue = WEXITSTATUS(status);
	}
}
#endif

static void SignalHandler(int sig)
{
	Warden::Signal = sig;
}

static void InitSignals()
{
	struct sigaction sa;

	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	sa.sa_handler = SignalHandler;

#ifndef _WIN32
	sigaction(SIGUSR1, &sa, NULL);
#endif
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	sa.sa_handler = SIG_IGN;

#ifndef _WIN32
	sigaction(SIGCHLD, &sa, NULL);
#endif
	sigaction(SIGPIPE, &sa, NULL);
}

/* Remove our PID file.  Done at exit. */

static void remove_pidfile()
{
	auto pidfile = Warden::ExpandData(Config->GetBlock("serverinfo").Get<const Warden::string>("pid"));
	if (!pidfile.empty())
		remove(pidfile.c_str());
}

/* Create our PID file and write the PID to it. */

static void write_pidfile()
{
	auto pidfile = Warden::ExpandData(Config->GetBlock("serverinfo").Get<const Warden::string>("pid"));
	if (Warden::NoPID || pidfile.empty())
		return;

#ifndef _WIN32
	std::ifstream oldstream(pidfile.str());
	if (oldstream.is_open())
	{
		pid_t oldpid = 0;
		oldstream >> oldpid;
		if (oldpid && oldpid != getpid() && kill(oldpid, 0) == 0)
			throw CoreException("Warden is already running with process id " + Warden::ToString(oldpid));
	}
	oldstream.close();
#endif

	std::ofstream stream(pidfile.str());
	if (!stream.is_open())
		throw CoreException("Can not write to PID file " + pidfile);
#ifdef _WIN32
		stream << GetCurrentProcessId() << std::endl;
#else
		stream << getpid() << std::endl;
#endif
	atexit(remove_pidfile);
}

static void setuidgid()
{
#ifndef _WIN32
	const auto &options = Config->GetBlock("options");
	uid_t uid = -1;
	gid_t gid = -1;

	if (!options.Get<const Warden::string>("user").empty())
	{
		errno = 0;
		struct passwd *u = getpwnam(options.Get<const Warden::string>("user").c_str());
		if (u == NULL)
			Log() << "Unable to setuid to " << options.Get<const Warden::string>("user") << ": " << Warden::LastError();
		else
			uid = u->pw_uid;
	}
	if (!options.Get<const Warden::string>("group").empty())
	{
		errno = 0;
		struct group *g = getgrnam(options.Get<const Warden::string>("group").c_str());
		if (g == NULL)
			Log() << "Unable to setgid to " << options.Get<const Warden::string>("group") << ": " << Warden::LastError();
		else
			gid = g->gr_gid;
	}

	for (const auto &li : Config->LogInfos)
	{
		for (const auto *lf : li.logfiles)
		{
			errno = 0;
			if (chown(lf->filename.c_str(), uid, gid) != 0)
				Log() << "Unable to change the ownership of " << lf->filename << " to " << uid << "/" << gid << ": " << Warden::LastError();
		}
	}

	if (static_cast<int>(gid) != -1)
	{
		if (setgid(gid) == -1)
			Log() << "Unable to setgid to " << options.Get<const Warden::string>("group") << ": " << Warden::LastError();
		else
			Log() << "Successfully set group to " << options.Get<const Warden::string>("group");
	}
	if (static_cast<int>(uid) != -1)
	{
		if (setuid(uid) == -1)
			Log() << "Unable to setuid to " << options.Get<const Warden::string>("user") << ": " << Warden::LastError();
		else
			Log() << "Successfully set user to " << options.Get<const Warden::string>("user");
	}
#endif
}

bool Warden::Init(int ac, char **av)
{
	/* Set file creation mask and group ID. */
#if defined(DEFUMASK) && HAVE_UMASK
	umask(DEFUMASK);
#endif

	Warden::UpdateTime();
	Warden::StartTime = Warden::CurTime;

	Serialize::RegisterTypes();

	/* Parse command line arguments */
	ParseCommandLineArguments(ac, av);

	if (GetCommandLineArgument("version", 'v'))
	{
		Log(LOG_TERMINAL) << "Warden-" << Warden::Version() << " -- " << Warden::VersionBuildString();
		Warden::ReturnValue = EXIT_SUCCESS;
		return false;
	}

	if (GetCommandLineArgument("help", 'h'))
	{
		Log(LOG_TERMINAL) << "Warden-" << Warden::Version() << " -- " << Warden::VersionBuildString();
		Log(LOG_TERMINAL) << "Warden IRC Services (https://github.com/TehPeGaSuS/warden)";
		Log(LOG_TERMINAL) << "Usage ./" << Warden::ServicesBin << " [options] ...";
		Log(LOG_TERMINAL) << "-c, --config=filename.conf";
		Log(LOG_TERMINAL) << "    --confdir=conf file directory";
		Log(LOG_TERMINAL) << "    --dbdir=database directory";
		Log(LOG_TERMINAL) << "-d, --debug[=level]";
		Log(LOG_TERMINAL) << "-h, --help";
		Log(LOG_TERMINAL) << "    --localedir=locale directory";
		Log(LOG_TERMINAL) << "    --logdir=log directory";
		Log(LOG_TERMINAL) << "    --moduledir=module directory";
		Log(LOG_TERMINAL) << "-e, --noexpire";
		Log(LOG_TERMINAL) << "-n, --nofork";
		Log(LOG_TERMINAL) << "-p, --nopid";
		Log(LOG_TERMINAL) << "    --nothird";
		Log(LOG_TERMINAL) << "    --protocoldebug";
		Log(LOG_TERMINAL) << "-r, --readonly";
		Log(LOG_TERMINAL) << "-s, --support";
		Log(LOG_TERMINAL) << "-v, --version";
		Log(LOG_TERMINAL) << "";
		Log(LOG_TERMINAL) << "Further support is available from https://github.com/TehPeGaSuS/warden/discussions";
		Warden::ReturnValue = EXIT_SUCCESS;
		return false;
	}

	if (GetCommandLineArgument("nofork", 'n'))
		Warden::NoFork = true;

	if (GetCommandLineArgument("support", 's'))
	{
		Warden::NoFork = Warden::NoThird = true;
		++Warden::Debug;
	}

	if (GetCommandLineArgument("readonly", 'r'))
		Warden::ReadOnly = true;

	if (GetCommandLineArgument("nothird"))
		Warden::NoThird = true;

	if (GetCommandLineArgument("nopid", 'p'))
		Warden::NoPID = true;

	if (GetCommandLineArgument("noexpire", 'e'))
		Warden::NoExpire = true;

	if (GetCommandLineArgument("nodb", 'b'))
		Warden::NoDB = true;

	if (GetCommandLineArgument("protocoldebug"))
		Warden::ProtocolDebug = true;

	Warden::string arg;
	if (GetCommandLineArgument("debug", 'd', arg))
	{
		if (!arg.empty())
		{
			auto level = Warden::TryConvert<unsigned>(arg);
			if (!level.has_value())
				throw CoreException("Invalid option given to --debug");
			Warden::Debug = level.value();
		}
		else
			++Warden::Debug;
	}

	if (GetCommandLineArgument("config", 'c', arg))
	{
		if (arg.empty())
			throw CoreException("The --config option requires a file name");
		ServicesConf = Configuration::File(arg, false);
	}

	if (GetCommandLineArgument("confdir", 0, arg))
	{
		if (arg.empty())
			throw CoreException("The --confdir option requires a path");
		Warden::ConfigDir = arg;
	}

	if (GetCommandLineArgument("dbdir", 0, arg))
	{
		if (arg.empty())
			throw CoreException("The --dbdir option requires a path");
		Warden::DataDir = arg;
	}

	if (GetCommandLineArgument("localedir", 0, arg))
	{
		if (arg.empty())
			throw CoreException("The --localedir option requires a path");
		Warden::LocaleDir = arg;
	}

	if (GetCommandLineArgument("moduledir", 0, arg))
	{
		if (arg.empty())
			throw CoreException("The --moduledir option requires a path");
		Warden::ModuleDir = arg;
	}

	if (GetCommandLineArgument("logdir", 0, arg))
	{
		if (arg.empty())
			throw CoreException("The --logdir option requires a path");
		Warden::LogDir = arg;
	}

	Log(LOG_TERMINAL) << "Warden " << Warden::Version() << ", " << Warden::VersionBuildString();

	/* Chdir to Warden data directory. */
	Log() << "Moving to " << Warden::ServicesDir;
	if (chdir(Warden::ServicesDir.c_str()) != 0)
	{
		throw CoreException("Unable to chdir to " + Warden::ServicesDir + ": " + Warden::LastError());
	}

	Log(LOG_TERMINAL) << "Using configuration file " << Warden::ExpandConfig(ServicesConf.GetName());

#ifndef _WIN32
	/* Fork to background */
	if (!Warden::NoFork)
	{
		/* Install these before fork() - it is possible for the child to
		 * connect and kill() the parent before it is able to install the
		 * handler.
		 */
		struct sigaction sa, old_sigusr2, old_sigchld;

		sa.sa_flags = 0;
		sigemptyset(&sa.sa_mask);
		sa.sa_handler = parent_signal_handler;

		sigaction(SIGUSR2, &sa, &old_sigusr2);
		sigaction(SIGCHLD, &sa, &old_sigchld);

		int i = fork();
		if (i > 0)
		{
			sigset_t mask;

			sigemptyset(&mask);
			sigsuspend(&mask);

			return false;
		}
		else if (i == -1)
		{
			Log() << "Error, unable to fork: " << Warden::LastError();
			Warden::NoFork = true;
		}

		/* Child doesn't need these */
		sigaction(SIGUSR2, &old_sigusr2, NULL);
		sigaction(SIGCHLD, &old_sigchld, NULL);
	}

#endif

	/* Initialize the socket engine. Note that some engines can not survive a fork(), so this must be here. */
	SocketEngine::Init();

	/* Read configuration file; exit if there are problems. */
	try
	{
		Config = new Configuration::Conf();
	}
	catch (const ConfigException &ex)
	{
		Log(LOG_TERMINAL) << ex.GetReason();
		Log(LOG_TERMINAL) << "*** Support resources: Read through the warden.conf self-contained";
		Log(LOG_TERMINAL) << "*** documentation. Read the documentation files found in the 'docs'";
		Log(LOG_TERMINAL) << "*** folder. Ask for help at https://github.com/TehPeGaSuS/warden/discussions";
		throw CoreException("Configuration file failed to validate");
	}

	/* Create me */
	const auto &block = Config->GetBlock("serverinfo");
	Me = new Server(NULL, block.Get<const Warden::string>("name"), block.Get<const Warden::string>("description"), block.Get<const Warden::string>("id"));
	for (const auto &[_, bi] : *BotListByNick)
	{
		bi->server = Me;
		++Me->users;
	}

	/* Announce ourselves to the logfile. */
	Log() << "Warden " << Warden::Version() << " starting up" << (Warden::Debug || Warden::ReadOnly ? " (options:" : "") << (Warden::Debug ? " debug" : "") << (Warden::ReadOnly ? " readonly" : "") << (Warden::Debug || Warden::ReadOnly ? ")" : "");

	InitSignals();

	/* Initialize multi-language support */
	Language::InitLanguages();

	/* load modules */
	Log() << "Loading modules...";
	for (const auto &[_,  block] : Config->GetBlocks("module"))
	{
		const auto res = ModuleManager::LoadModule(block.Get<const Warden::string>("name"), NULL);
		if (res == MOD_ERR_CONFIG)
		{
			Log(LOG_TERMINAL) << "You must fix this issue before Warden will start.";
			Warden::ReturnValue = EXIT_FAILURE;
			return false;
		}
	}

#ifndef _WIN32
	/* If we're root, issue a warning now */
	if (!getuid() && !getgid())
	{
		/* If we are configured to setuid later, don't issue a warning */
		const auto &options = Config->GetBlock("options");
		if (options.Get<const Warden::string>("user").empty())
		{
			std::cerr << "WARNING: You are currently running Warden as the root superuser. Warden does not" << std::endl;
			std::cerr << "         require root privileges to run, and it is discouraged that you run Warden" << std::endl;
			std::cerr << "         as the root superuser." << std::endl;
			std::this_thread::sleep_for(std::chrono::seconds(3));
		}
	}

	/* We won't background later, so we should setuid now */
	if (Warden::NoFork)
		setuidgid();
#endif

	if (!Warden::NoDB)
	{
		if (!ModuleManager::FindFirstOf(DATABASE, true))
			throw CoreException("You must load a non-deprecated database module!");

		if (!ModuleManager::FindFirstOf(ENCRYPTION, true))
			throw CoreException("You must load a non-deprecated encryption module!");
	}

	if (!IRCD)
		throw CoreException("You must load a protocol module!");

	/* Write our PID to the PID file. */
	write_pidfile();

	Log(LOG_TERMINAL) << "Using IRCd protocol " << IRCD->GetProtocolName() << " (" << IRCD->owner->name << ")";

	/* Auto assign sid if applicable */
	if (IRCD->RequiresID)
	{
		Warden::string sid = IRCD->SID_Retrieve();
		if (Me->GetSID() == Me->GetName())
			Me->SetSID(sid);
		for (const auto &[_, bi] : *BotListByNick)
			bi->GenerateUID();
	}

	/* Load up databases */
	Log() << "Loading databases...";
	EventReturn MOD_RESULT;
	FOREACH_RESULT(OnLoadDatabase, MOD_RESULT, ());
	static_cast<void>(MOD_RESULT);
	Log() << "Databases loaded";

	FOREACH_MOD(OnPostInit, ());

	Serialize::CheckTypes();
	return true;
}
