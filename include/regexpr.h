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

#include "services.h"
#include "warden.h"
#include "service.h"

class CoreExport RegexException final
	: public CoreException
{
public:
	RegexException(const Warden::string &reason = "") : CoreException(reason) { }

	virtual ~RegexException() noexcept = default;
};

class CoreExport Regex
{
	Warden::string expression;
protected:
	Regex(const Warden::string &expr) : expression(expr) { }
public:
	virtual ~Regex() = default;
	const Warden::string &GetExpression() { return expression; }
	virtual bool Matches(const Warden::string &str) = 0;
};

class CoreExport RegexProvider
	: public Service
{
public:
	RegexProvider(Module *o, const Warden::string &n) : Service(o, "Regex", n) { }
	virtual Regex *Compile(const Warden::string &) = 0;
};
