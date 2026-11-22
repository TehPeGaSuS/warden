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

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <algorithm>
#include <bitset>
#include <deque>
#include <exception>
#include <fstream>
#include <functional>
#include <istream>
#include <list>
#include <map>
#include <set>
#include <sstream>
#include <vector>

#ifndef _WIN32
# include <unistd.h>
#endif

#include "defs.h"
#include "sysconf.h"

#define _(x) x
#define N_(x, y) x, y

#ifndef _WIN32
# define DllExport __attribute__ ((visibility ("default")))
# define CoreExport __attribute__ ((visibility ("default")))
# define warden_close close
#else
# include "warden_windows.h"
#endif
