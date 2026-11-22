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

#include "modules/httpd.h"

/* A basic file server. Used for serving non-static non-binary content on disk. */
class TemplateFileServer final
{
	Warden::string file_name;
public:
	struct Replacements final
		: std::multimap<Warden::string, Warden::string>
	{
		Warden::string &operator[](const Warden::string &key)
		{
			return emplace(key, "")->second;
		}
	};

	TemplateFileServer(const Warden::string &f_n);

	void Serve(HTTP::Provider *, const Warden::string &, HTTP::Client *, HTTP::Message &, HTTP::Reply &, Replacements &);
};
