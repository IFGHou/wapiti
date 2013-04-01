import socket
from attack import Attack
from vulnerability import Vulnerability
from vulnerabilitiesdescriptions import VulnerabilitiesDescriptions as VulDescrip
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

class mod_file(Attack):
    """
    This class implements a file handling attack
    """

    CONFIG_FILE = "fileHandlingPayloads.txt"
  
    name = "file"

    warning_messages = [
            ("java.io.FileNotFoundException:",        "Java include/open"),
            ("fread(): supplied argument is not",     "fread()"),
            ("fpassthru(): supplied argument is not", "fpassthru()"),
            ("for inclusion (include_path=",          "include()"),
            ("Failed opening required",               "require()"),
            ("Warning: file(",                        "file()"),
            ("<b>Warning</b>:  file(",                "file()"),
            ("Warning: readfile(",                    "readfile()"),
            ("<b>Warning:</b>  readfile(",            "readfile()"),
            ("Warning: file_get_contents(",           "file_get_contents()"),
            ("<b>Warning</b>:  file_get_contents(",   "file_get_contents()"),
            ("Warning: show_source(",                 "show_source()"),
            ("<b>Warning:</b>  show_source(",         "show_source()"),
            ("Warning: highlight_file(",              "highlight_file()"),
            ("<b>Warning:</b>  highlight_file(",      "highlight_file()"),
            ("System.IO.FileNotFoundException:",      ".NET File.Open*"),
            ("error '800a0046'",                      "VBScript OpenTextFile")
            ]

    def __init__(self, HTTP, xmlRepGenerator):
        Attack.__init__(self, HTTP, xmlRepGenerator)
        self.payloads = self.loadPayloads(self.CONFIG_DIR + "/" + self.CONFIG_FILE)

    def __findPatternInResponse(self, data, warn):
        """This method searches patterns in the response from the server"""
        err = ""
        inc = 0
        if "root:x:0:0" in data:
            err = "Unix include/fread"
            inc = 1
        if "root:*:0:0" in data:
            err = "BSD include/fread"
            inc = 1
        if "[boot loader]" in data:
            err = "Windows include/fread"
            inc = 1
        if "<title>Google</title>" in data:
            err = _("Remote include")
            inc = 1
        for pattern, funcname in self.warning_messages:
            if pattern in data and warn == 0:
                err = "Warning " + funcname
                warn = 1
                break
        return err, inc, warn

    def attackGET(self, http_res):
        """This method performs the file handling attack with method GET"""
        page = http_res.path
        params_list = http_res.get_params
        resp_headers = http_res.headers
        referer = http_res.referer
        headers = {}
        if referer:
            headers["referer"] = referer

        if not params_list:
            # Do not attack application-type files
            if not "content-type" in resp_headers:
                # Sometimes there's no content-type... so we rely on the document extension
                if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
                    return
            elif not "text" in resp_headers["content-type"]:
                return

            warn = 0
            inc = 0
            err500 = 0

            for payload in self.payloads:
                err = ""
                url = page + "?" + self.HTTP.quote(payload)
                if url not in self.attackedGET:
                    if self.verbose == 2:
                        print "+", url
                    self.attackedGET.append(url)
                    evil_req = HTTP.HTTPResource(url)
                    if inc:
                        continue
                    try:
                        data, code = self.HTTP.send(evil_req, headers=headers).getPageCode()
                    except requests.exceptions.Timeout, timeout:
                        data = ""
                        code = "408"
                        err = ""
                        self.reportGen.logVulnerability(category=Vulnerability.RES_CONSUMPTION,
                                                        level=Vulnerability.MEDIUM_LEVEL_VULNERABILITY,
                                                        request=evil_req,
                                                        info=_("Timeout (QUERY_STRING) in") + " " + str(page))
                        print _("Timeout (QUERY_STRING) in"), page
                        print "  " + _("caused by") + ":", evil_req.url
                    else:
                        err, inc, warn = self.__findPatternInResponse(data, warn)
                    if err != "":
                        self.reportGen.logVulnerability(category=Vulnerability.FILE_HANDLING,
                                                        level=Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                                        request=evil_req,
                                                        info=str(err) + " " + _("(QUERY_STRING) in") + " " + str(page))
                        print err, _("(QUERY_STRING) in"), page
                        print "  " + _("Evil url") + ":", url
                    else:
                        if code == "500" and err500 == 0:
                            err500 = 1
                            self.reportGen.logVulnerability(category=Vulnerability.FILE_HANDLING,
                                                            level=Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                                            request=evil_req,
                                                            info=VulDescrip.ERROR_500 + "\n" + VulDescrip.ERROR_500_DESCRIPTION)
                            print _("500 HTTP Error code with")
                            print "  " + _("Evil url") + ":", url

        for i in range(len(params_list)):
            warn = 0
            inc = 0
            err500 = 0
            param_name = self.HTTP.quote(params_list[i][0])
            saved_value = params_list[i][1]
            for payload in self.payloads:
                err = ""
                params_list[i][1] = self.HTTP.quote(payload)
                url = page + "?" + self.HTTP.encode(params_list)
                if url not in self.attackedGET:
                    if self.verbose == 2:
                        print "+", url
                    self.attackedGET.append(url)
                    if inc == 1:
                        continue
                    evil_req = HTTP.HTTPResource(url)
                    try:
                        data, code = self.HTTP.send(evil_req, headers=headers).getPageCode()
                    except requests.exceptions.Timeout, timeout:
                        data = ""
                        code = "408"
                        err = ""
                        self.reportGen.logVulnerability(category=Vulnerability.RES_CONSUMPTION,
                                                        level=Vulnerability.MEDIUM_LEVEL_VULNERABILITY,
                                                        request=evil_req,
                                                        info=err + " (" + param_name + ")")
                        print _("Timeout") + " (" + param_name + ") " + _("in"), page
                        print "  " + _("caused by") + ":", evil_req.url
                    else:
                        err, inc, warn = self.__findPatternInResponse(data, warn)
                    if err != "":
                        self.reportGen.logVulnerability(category=Vulnerability.FILE_HANDLING,
                                                        level=Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                                        request=evil_req,
                                                        info=err + " (" + param_name + ")")
                        if self.color == 0:
                            print err, "(" + param_name + ") " + _("in"), page
                            print "  " + _("Evil url") + ":", evil_req.url
                        else:
                            print err, ":", evil_req.url.replace(param_name + "=", self.RED + param_name + self.STD + "=")
                    else:
                        if code == "500" and err500 == 0:
                            err500 = 1
                            self.reportGen.logVulnerability(category=Vulnerability.FILE_HANDLING,
                                                            level=Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                                            request=evil_req,
                                                            info=VulDescrip.ERROR_500 + "\n" + VulDescrip.ERROR_500_DESCRIPTION)
                            print _("500 HTTP Error code with")
                            print "  " + _("Evil url") + ":", evil_req.url
            params_list[i][1] = saved_value

    def attackPOST(self, form):
        """This method performs the file handling attack with method POST"""

        # copies
        get_params  = form.get_params
        post_params = form.post_params
        file_params = form.file_params
        referer = form.referer

        err = ""
        for param_list in [get_params, post_params, file_params]:
            for i in xrange(len(param_list)):
                warn = 0
                inc = 0
                err500 = 0

                saved_value = param_list[i][1]
                param_name = self.HTTP.quote(param_list[i][0])
                param_list[i][1] = "__FILE__"
                attack_pattern = HTTP.HTTPResource(form.path,
                                                   method=form.method,
                                                   get_params=get_params,
                                                   post_params=post_params,
                                                   file_params=file_params)
                if attack_pattern not in self.attackedPOST:
                    self.attackedPOST.append(attack_pattern)
                    for payload in self.payloads:
                        param_list[i][1] = payload
                        evil_req = HTTP.HTTPResource(form.path,
                                method=form.method,
                                get_params=get_params,
                                post_params=post_params,
                                file_params=file_params,
                                referer=referer)
                        if self.verbose == 2:
                            print "+", evil_req
                        try:
                            data, code = self.HTTP.send(evil_req).getPageCode()
                        except requests.exceptions.Timeout, timeout:
                            data = ""
                            code = "408"
                            self.reportGen.logVulnerability(category=Vulnerability.RES_CONSUMPTION,
                                                            level=Vulnerability.MEDIUM_LEVEL_VULNERABILITY,
                                                            request=evil_req,
                                                            info=_("Timeout coming from") + " " + referer)
                            print _("Timeout in"), evil_req.url
                            print "  " + _("with params") + " =", self.HTTP.encode(evil_req.post_params)
                            print "  " + _("coming from"), referer
                        else:
                            err, inc, warn = self.__findPatternInResponse(data, warn)
                        if err != "":
                            self.reportGen.logVulnerability(category=Vulnerability.FILE_HANDLING,
                                                            level=Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                                            request=evil_req,
                                                            info=err + " " + _("coming from") + " " + referer)
                            print err, _("in"), evil_req.url
                            if self.color == 1:
                                print "  " + _("with params") + " =", \
                                        self.HTTP.encode(evil_req.post_params).replace(param_name + "=", self.RED + param_name + self.STD + "=")
                            else:
                                print "  " + _("with params") + " =", self.HTTP.encode(evil_req.post_params)
                            print "  " + _("coming from"), referer
                            if inc:
                                break

                        else:
                            if code == "500" and err500 == 0:
                                err500 = 1
                                self.reportGen.logVulnerability(category=Vulnerability.FILE_HANDLING,
                                                                level=Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                                                request=evil_req,
                                                                info=_("500 HTTP Error code coming from") + " " + \
                                                                       referer + "\n" + VulDescrip.ERROR_500_DESCRIPTION)
                                print _("500 HTTP Error code in"), evil_req.post_params
                                print "  " + _("with params") + " =", self.HTTP.encode(evil_req.post_params)
                                print "  " + _("coming from"), referer
                param_list[i][1] = saved_value
