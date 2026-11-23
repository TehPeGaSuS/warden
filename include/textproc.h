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

#define WARDEN_FORMAT(LAST, FORMAT, BUFFER) \
	do { \
		va_list _valist; \
		va_start(_valist, LAST); \
		(BUFFER) = Warden::Format(_valist, (FORMAT)); \
		va_end(_valist); \
	} while (false);

namespace Warden
{
	/** Encode a string as base-64.
	 * @param str The string to encode as base-64 .
	 */
	extern CoreExport Warden::string B64Encode(const Warden::string &str);

	/** Decode a string from base-64.
	 * @param str The string to decode from base-64.
	 */
	extern CoreExport Warden::string B64Decode(const Warden::string &str);

	/** Calculates the levenshtein distance between two strings.
	 * @param s1 The first string.
	 * @param s2 The second string.
	 */
	extern CoreExport size_t Distance(const Warden::string &s1, const Warden::string &s2);

	/** Expands a path fragment that is relative to the base directory.
	 * @param base The base directory that it is relative to.
	 * @param fragment The fragment to expand.
	 */
	extern CoreExport Warden::string Expand(const Warden::string &base, const Warden::string &fragment);

	/** Expands a config path. */
	inline auto ExpandConfig(const Warden::string &path) { return Expand(ConfigDir, path); }

	/** Expands a data path. */
	inline auto ExpandData(const Warden::string &path) { return Expand(DataDir, path); }

	/** Expands a locale path. */
	inline auto ExpandLocale(const Warden::string &path) { return Expand(LocaleDir, path); }

	/** Expands a log path. */
	inline auto ExpandLog(const Warden::string &path) { return Expand(LogDir, path); }

	/** Expands a module path. */
	inline auto ExpandModule(const Warden::string &path) { return Expand(ModuleDir, path); }

	/** Formats a string using one or more values. This uses snprintf internally but with a flexible buffer.
	 * @param fmt The message to format.
	 */
	extern CoreExport Warden::string Format(const char *fmt, ...) ATTR_FORMAT(1, 2);

	/** Formats a string using a list of values. This uses snprintf internally but with a flexible buffer.
	 * @param valist A list of values to format the message with.
	 * @param fmt The message to format.
	 */
	extern CoreExport Warden::string Format(va_list &valist, const char *fmt) ATTR_FORMAT(2, 0);

	/** Formats a CTCP message for sending to a client.
	 * @param name The name of the CTCP.
	 * @param body If present then the body of the CTCP.
	 * @return A formatted CTCP ready to send to a client.
	 */
	extern CoreExport Warden::string FormatCTCP(const Warden::string &name, const Warden::string &body = "");

	/** Formats a date/time as an IS0 8601 timestamp.
	 * @param ts UNIX timestamp to format.
	 * @param ms Number of milliseconds to format.
	 */
	extern CoreExport Warden::string FormatISO8601(time_t ts, unsigned long long ms);

	/** Parses a CTCP message received from a client.
	 * @param text The raw message to parse.
	 * @param name The location to store the name of the CTCP.
	 * @param body The location to store body of the CTCP if one is present.
	 * @return True if the message was a well formed CTCP; otherwise, false.
	 */
	extern CoreExport bool ParseCTCP(const Warden::string &text, Warden::string &name, Warden::string &body);

	/** Remove all formatting characters from a string.
	 * @param text A string containing formatting characters.
	 * @return A copy of \p text with all formatting characters removed.
	 */
	extern CoreExport Warden::string RemoveFormatting(const Warden::string &text);

	/** Replace characters that are unsafe in an IRC wire message with a space character.
	 * @param text A string to replace unsafe characters within.
	 * @return A copy of \p text with all unsafe characters replaced.
	 */
	extern CoreExport Warden::string ReplaceUnsafe(const Warden::string &text);

	/** Replaces template variables within a string with values from a map.
	 * {name} is replaced with the value of name, {?name}...{/name} is only
	 * kept if name has a non-empty value and {!name}...{/name} only if not.
	 * @param str The string to template from.
	 * @param vars The variables to replace within the string.
	 * @return The specified string with all variables replaced within it.
	 */
	extern CoreExport Warden::string Template(const Warden::string &str, const Warden::map<Warden::string> &vars);
}

class CoreExport ExampleWrapper final
{
private:
	struct Example final
	{
		Warden::string example;
		Warden::string description;
		Warden::string privilege;
	};
	std::vector<Example> entries;

public:
	ExampleWrapper &AddEntry(const Warden::string &example, const Warden::string &desc, const Warden::string &priv = "");
	void SendTo(CommandSource &source);
};

class CoreExport HelpWrapper final
{
private:
	std::vector<std::pair<Warden::string, Warden::string>> entries;
	size_t longest = 0;

public:
	void AddEntry(const Warden::string &name, const Warden::string &desc);
	void SendTo(CommandSource &source);
};

class CoreExport InfoFormatter final
{
private:
	size_t longest = 0;
	NickCore *nc;
	std::vector<Warden::string> options;
	std::vector<std::pair<Warden::string, Warden::string>> replies;

public:
	InfoFormatter(NickCore *nc);
	Warden::string &operator[](const Warden::string &key);
	void AddOption(const Warden::string &opt);
	void SendTo(CommandSource &source);
};

class CoreExport LineWrapper final
{
private:
	std::vector<Warden::string> formatting;
	const size_t max_length;
	Warden::string text;

public:
	LineWrapper(const Warden::string &t, size_t ml = 0);
	bool GetLine(Warden::string &out);
};

class CoreExport ListFormatter final
{
public:
	using ListEntry = std::map<Warden::string, Warden::string>;
	using FlexibleFormatFn = std::function<Warden::string(ListEntry &)>;

private:
	std::vector<Warden::string> columns;
	std::vector<ListEntry> entries;
	FlexibleFormatFn flexiblerow;
	NickCore *nc;
	void SendFixed(CommandSource &source);
	void SendFlexible(CommandSource &source);

public:
	ListFormatter(NickCore *nc);
	ListFormatter &AddColumn(const Warden::string &name);
	void AddEntry(const ListEntry &entry);
	bool IsEmpty() const;
	void SendTo(CommandSource &source);
	void SetFlexible(const Warden::string &format);
	void SetFlexible(const FlexibleFormatFn &formatter);
};
