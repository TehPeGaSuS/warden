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

WebCPanel::ChanServ::Modes::Modes(const Warden::string &cat, const Warden::string &u) : WebPanelProtectedPage(cat, u)
{
}

bool WebCPanel::ChanServ::Modes::OnRequest(HTTP::Provider *server, const Warden::string &page_name, HTTP::Client *client, HTTP::Message &message, HTTP::Reply &reply, NickAlias *na, TemplateFileServer::Replacements &replacements)
{
	TemplateFileServer Page("chanserv/modes.html");

	BuildChanList(na, replacements);

	const Warden::string chname = WebPanel::GetRequestData(message.get_data, "channel");
	if (chname.empty())
	{
		Page.Serve(server, page_name, client, message, reply, replacements);
		return true;
	}

	replacements["ESCAPED_CHANNEL"] = HTTP::URLEncode(chname);
	ChannelInfo *ci = ChannelInfo::Find(chname);

	if (!ci)
	{
		Page.Serve(server, page_name, client, message, reply, replacements);
		return true;
	}

	Channel *c = Channel::Find(chname);

	if (!c)
	{
		replacements["MESSAGES"] = Warden::Format(CHAN_X_NOT_IN_USE, chname.c_str());
		Page.Serve(server, page_name, client, message, reply, replacements);
		return true;
	}

	AccessGroup u_access = ci->AccessFor(na->nc);
	bool has_priv = na->nc->IsServicesOper() && na->nc->o->ot->HasPriv("chanserv/administration");

	if (!u_access.HasPriv("MODE") && !has_priv)
	{
		replacements["MESSAGES"] = "Access denied.";
		Page.Serve(server, page_name, client, message, reply, replacements);
		return true;
	}

	replacements["MODE"] = "YES";

	/* build a list with the names of all listmodes */
	for (auto *cm : ModeManager::GetChannelModes())
	{
		if (cm->type == MODE_LIST && cm->mchar)
			replacements["LISTMODES"] = cm->mchar;
	}

	const Warden::string mode = WebPanel::GetRequestData(message.get_data, "m");
	if (mode.empty())
	{
		Page.Serve(server, page_name, client, message, reply, replacements);
		return true;
	}
	replacements["ESCAPED_MODE"] = HTTP::URLEncode(mode);

	ChannelMode *cm = ModeManager::FindChannelModeByChar(mode[0]);
	if (cm)
	{
		const Warden::string mask = WebPanel::GetRequestData(message.get_data, "mask");
		const Warden::string pmask = WebPanel::GetRequestData(message.post_data, "mask");
		if (message.get_data.count("del") && !mask.empty())
		{
			std::vector<Warden::string> params;
			params.push_back(ci->name);
			params.emplace_back("SET");
			params.push_back("-" + Warden::string(cm->mchar));
			params.push_back(mask);
			WebPanel::RunCommand(client, na->nc->display, na->nc, "ChanServ", "chanserv/mode", params, replacements);
		}
		else if (!pmask.empty())
		{
			std::vector<Warden::string> params;
			params.push_back(ci->name);
			params.emplace_back("SET");
			params.push_back("+" + Warden::string(cm->mchar));
			params.push_back(pmask);
			WebPanel::RunCommand(client, na->nc->display, na->nc, "ChanServ", "chanserv/mode", params, replacements);
		}

		for (const auto &mask : c->GetModeList(cm->name))
			replacements["MASKS"] = mask;
	}

	Page.Serve(server, page_name, client, message, reply, replacements);
	return true;
}

std::set<Warden::string> WebCPanel::ChanServ::Modes::GetData()
{
	std::set<Warden::string> v;
	v.insert("channel");
	return v;
}
