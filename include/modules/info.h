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

class OperInfo
{
protected:
	OperInfo() = default;

	OperInfo(const Warden::string &t, const Warden::string &i, const Warden::string &a, time_t c)
		: target(t)
		, info(i)
		, adder(a)
		, created(c)
	{
	}

public:
	Warden::string target;
	Warden::string info;
	Warden::string adder;
	time_t created = 0;

	virtual ~OperInfo() = default;
};

class OperInfoList
	: public Serialize::Checker<std::vector<OperInfo *>>
{
public:
	OperInfoList()
		: Serialize::Checker<std::vector<OperInfo *>>("OperInfo")
	{
	}

	virtual ~OperInfoList()
	{
		for (auto *info : *(*this))
			delete info;
	}

	virtual OperInfo *Create() = 0;
};
