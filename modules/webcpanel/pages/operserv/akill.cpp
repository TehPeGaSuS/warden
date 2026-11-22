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

#include "../../webcpanel.h"

WebCPanel::OperServ::Akill::Akill(const Warden::string &cat, const Warden::string &u) : WebPanelProtectedPage(cat, u)
{
}

bool WebCPanel::OperServ::Akill::OnRequest(HTTP::Provider *server, const Warden::string &page_name, HTTP::Client *client, HTTP::Message &message, HTTP::Reply &reply, NickAlias *na, TemplateFileServer::Replacements &replacements)
{

	static ServiceReference<XLineManager> akills("XLineManager","xlinemanager/sgline");

	if (!na->nc->o || !na->nc->o->ot->HasCommand("operserv/akill"))
	{
		replacements["NOACCESS"];
	}
	else
	{
		if (akills->GetCount() == 0)
			replacements["AKILLS"] = "No Akills to display.";

		const Warden::string expiry = WebPanel::GetRequestData(message.post_data, "expiry");
		const Warden::string mask = WebPanel::GetRequestData(message.post_data, "mask");
		const Warden::string reason = WebPanel::GetRequestData(message.post_data, "reason");
		if (!expiry.empty() && !mask.empty() && !reason.empty())
		{
			std::vector<Warden::string> params;
			std::stringstream cmdstr;
			params.push_back("ADD");
			cmdstr << "+" << expiry;
			cmdstr << " " << mask;
			cmdstr << " " << reason;
			params.push_back(cmdstr.str());
			WebPanel::RunCommand(client, na->nc->display, na->nc, "OperServ", "operserv/akill", params, replacements);
		}



		const Warden::string number = WebPanel::GetRequestData(message.get_data, "number");
		if (message.get_data.count("del") && !number.empty())
		{
			std::vector<Warden::string> params;
			params.push_back("DEL");
			params.push_back(number);
			WebPanel::RunCommand(client, na->nc->display, na->nc, "OperServ", "operserv/akill", params, replacements);
		}

		for (unsigned i = 0, end = akills->GetCount(); i < end; ++i)
		{
			const XLine *x = akills->GetEntry(i);
			replacements["NUMBER"] = Warden::ToString(i + 1);
			replacements["HOST"] = x->mask;
			replacements["SETTER"] = x->by;
			replacements["TIME"] = Warden::strftime(x->created, NULL, true);
			replacements["EXPIRE"] = Warden::Expires(x->expires, na->nc);
			replacements["REASON"] = x->reason;
		}
	}

	TemplateFileServer page("operserv/akill.html");
	page.Serve(server, page_name, client, message, reply, replacements);
	return true;
}
