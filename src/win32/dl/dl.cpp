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
#include "warden.h"

void *dlopen(const char *filename, int)
{
	return LoadLibrary(filename);
}

char *dlerror(void)
{
	static Warden::string err;
	err = Warden::LastError();
	SetLastError(0);
	return err.empty() ? NULL : const_cast<char *>(err.c_str());
}

void *dlsym(void *handle, const char *symbol)
{
	return GetProcAddress(reinterpret_cast<HMODULE>(handle), symbol);
}

int dlclose(void *handle)
{
	return !FreeLibrary(reinterpret_cast<HMODULE>(handle));
}
