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
#include "modules/nickserv/cert.h"

WebCPanel::NickServ::Cert::Cert(const Warden::string &cat, const Warden::string &u) : WebPanelProtectedPage(cat, u)
{
}

bool WebCPanel::NickServ::Cert::OnRequest(HTTP::Provider *server, const Warden::string &page_name, HTTP::Client *client, HTTP::Message &message, HTTP::Reply &reply, NickAlias *na, TemplateFileServer::Replacements &replacements)
{
	const Warden::string certfp = WebPanel::GetRequestData(message.post_data, "certfp");
	const Warden::string mask = WebPanel::GetRequestData(message.get_data, "mask");
	if (!certfp.empty())
	{
		std::vector<Warden::string> params;
		params.push_back("ADD");
		params.push_back(certfp);

		WebPanel::RunCommand(client, na->nc->display, na->nc, "NickServ", "nickserv/cert", params, replacements);
	}
	else if (message.get_data.count("del") && !mask.empty())
	{
		std::vector<Warden::string> params;
		params.push_back("DEL");
		params.push_back(mask);

		WebPanel::RunCommand(client, na->nc->display, na->nc, "NickServ", "nickserv/cert", params, replacements);
	}

	auto *cl = na->nc->GetExt<::NickServ::CertList>(NICKSERV_CERT_EXT);
	if (cl)
		for (unsigned i = 0; i < cl->GetCertCount(); ++i)
			replacements["CERTS"] = cl->GetCert(i)->fingerprint;

	TemplateFileServer page("nickserv/cert.html");
	page.Serve(server, page_name, client, message, reply, replacements);
	return true;
}
