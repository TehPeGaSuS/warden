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

#include "../webcpanel.h"

bool WebCPanel::Confirm::OnRequest(HTTP::Provider *server, const Warden::string &page_name, HTTP::Client *client, HTTP::Message &message, HTTP::Reply &reply)
{
	TemplateFileServer::Replacements replacements;
	replacements["TITLE"] = page_title;

	if (!WebPanel::IsAllowedOrigin(message))
	{
		reply.error = HTTP::BAD_REQUEST;
		reply.Write("Invalid request origin.");
		return true;
	}

	const Warden::string user = WebPanel::GetRequestData(message.post_data, "username");
	const Warden::string pass = WebPanel::GetRequestData(message.post_data, "password");
	if (!user.empty() && !pass.empty())
	{
		std::vector<Warden::string> params;
		params.push_back(pass);
		const Warden::string email = WebPanel::GetRequestData(message.post_data, "email");
		if (!email.empty())
			params.push_back(email);

		WebPanel::RunCommand(client, user, NULL, "NickServ", "nickserv/register", params, replacements);
	}

	TemplateFileServer page("confirm.html");

	page.Serve(server, page_name, client, message, reply, replacements);
	return true;
}
