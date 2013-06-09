from attack import Attack
from vulnerability import Vulnerability, Anomaly
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


class mod_blindsql(Attack):
    """
    This class implements an SQL Injection attack
    """

    CONFIG_FILE = "blindSQLPayloads.txt"
    blind_sql_payloads = []
    TIME_TO_SLEEP = 6
    name = "blindsql"
    require = ["sql"]
    PRIORITY = 6

    excludedGET = []
    excludedPOST = []

    MSG_VULN = _("Blind SQL vulnerability")

    def __init__(self, HTTP, xmlRepGenerator):
        Attack.__init__(self, HTTP, xmlRepGenerator)
        self.blind_sql_payloads = self.loadPayloads(self.CONFIG_DIR + "/" + self.CONFIG_FILE)

    def setTimeout(self, timeout):
        self.TIME_TO_SLEEP = str(1 + int(timeout))

    # first implementations for blind sql injection...
    # must had this to Vulnerability type
    def attackGET(self, http_res):
        """This method performs the Blind SQL attack with method GET"""
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

            pattern_url = page + "?__SQL__"
            if pattern_url in self.excludedGET:
                return

            if pattern_url not in self.attackedGET:
                self.attackedGET.append(pattern_url)
                err500 = 0
                for payload in self.blind_sql_payloads:
                    payload = self.HTTP.quote(payload.replace("__TIME__", self.TIME_TO_SLEEP))
                    url = page + "?" + payload
                    evil_req = HTTP.HTTPResource(url)
                    if self.verbose == 2:
                        print(u"+ {0}".format(evil_req.url))
                    try:
                        resp = self.HTTP.send(evil_req, headers=headers)
                        data, code = resp.getPageCode()
                    except requests.exceptions.Timeout:
                        self.logVuln(category=Vulnerability.BLIND_SQL_INJECTION,
                                     level=Vulnerability.HIGH_LEVEL,
                                     request=evil_req,
                                     parameter="QUERY_STRING",
                                     info=_("{0} via injection in the query string").format(self.MSG_VULN))
                        self.log(Vulnerability.MSG_QS_INJECT, self.MSG_VULN, page)
                        self.log(Vulnerability.MSG_EVIL_URL, evil_req.url)
                        break
                    else:
                        if code == "500" and err500 == 0:
                            err500 = 1
                            self.logAnom(category=Anomaly.ERROR_500,
                                         level=Anomaly.HIGH_LEVEL,
                                         request=evil_req,
                                         parameter="QUERY_STRING",
                                         info=Anomaly.MSG_QS_500)
                            self.log(Anomaly.MSG_500, page)
                            self.log(Anomaly.MSG_EVIL_URL, evil_req.url)
        else:
            for i in range(len(params_list)):
                saved_value = params_list[i][1]

                param_name = self.HTTP.quote(params_list[i][0])
                params_list[i][1] = "__SQL__"
                pattern_url = page + "?" + self.HTTP.encode(params_list)

                # This field was successfully attacked with a non-blind SQL injection
                if pattern_url in self.excludedGET:
                    params_list[i][1] = saved_value
                    continue

                if pattern_url not in self.attackedGET:
                    self.attackedGET.append(pattern_url)

                    err500 = 0
                    for payload in self.blind_sql_payloads:

                        payload = payload.replace("[VALUE]", saved_value)
                        params_list[i][1] = self.HTTP.quote(payload.replace("__TIME__", self.TIME_TO_SLEEP))
                        url = page + "?" + self.HTTP.encode(params_list)
                        evil_req = HTTP.HTTPResource(url)
                        if self.verbose == 2:
                            print(u"+ {0}".format(evil_req.url))
                        try:
                            resp = self.HTTP.send(evil_req, headers=headers)
                            data, code = resp.getPageCode()
                        except requests.exceptions.Timeout:
                            self.logVuln(category=Vulnerability.BLIND_SQL_INJECTION,
                                         level=Vulnerability.HIGH_LEVEL,
                                         request=evil_req,
                                         parameter=param_name,
                                         info=_("{0} via injection in "
                                                "the parameter {1}").format(self.MSG_VULN, param_name))
                            self.log(Vulnerability.MSG_PARAM_INJECT,
                                     self.MSG_VULN,
                                     page,
                                     param_name)
                            if self.color == 0:
                                self.log(Vulnerability.MSG_EVIL_URL, evil_req.url)
                            else:
                                self.log(Vulnerability.MSG_EVIL_URL,
                                         evil_req.url.replace(param_name + "=",
                                                              self.RED + param_name + self.STD + "="))
                            # One payload worked. Now jum to next field
                            break
                        else:
                            if code == "500" and err500 == 0:
                                err500 = 1
                                self.logAnom(category=Anomaly.ERROR_500,
                                             level=Anomaly.HIGH_LEVEL,
                                             request=evil_req,
                                             parameter=param_name,
                                             info=Anomaly.MSG_PARAM_500.format(param_name))
                                self.log(Anomaly.MSG_500, page)
                                self.log(Anomaly.MSG_EVIL_URL, evil_req.url)
                params_list[i][1] = saved_value

    def attackPOST(self, form):
        """This method performs the Blind SQL attack with method POST"""

        # copies
        get_params = form.get_params
        post_params = form.post_params
        file_params = form.file_params
        referer = form.referer

        for param_list in [get_params, post_params, file_params]:
            for i in xrange(len(param_list)):
                saved_value = param_list[i][1]
                param_name = self.HTTP.quote(param_list[i][0])
                param_list[i][1] = "__SQL__"
                attack_pattern = HTTP.HTTPResource(form.path,
                                                   method=form.method,
                                                   get_params=get_params,
                                                   post_params=post_params,
                                                   file_params=file_params)

                if attack_pattern in self.excludedPOST:
                    param_list[i][1] = saved_value
                    continue

                err500 = 0
                if attack_pattern not in self.attackedPOST:
                    self.attackedPOST.append(attack_pattern)
                    for payload in self.blind_sql_payloads:
                        param_list[i][1] = payload.replace("__TIME__", self.TIME_TO_SLEEP)
                        evil_req = HTTP.HTTPResource(form.path,
                                                     method=form.method,
                                                     get_params=get_params,
                                                     post_params=post_params,
                                                     file_params=file_params,
                                                     referer=referer)

                        if self.verbose == 2:
                            print(u"+ {0}".format(evil_req))
                        try:
                            resp = self.HTTP.send(evil_req)
                            data, code = resp.getPageCode()
                        except requests.exceptions.Timeout:
                            # Timeout means time-based SQL injection
                            self.logVuln(category=Vulnerability.BLIND_SQL_INJECTION,
                                         level=Vulnerability.HIGH_LEVEL,
                                         request=evil_req,
                                         parameter=param_name,
                                         info=_("{0} via injection in the "
                                                "parameter {1}").format(self.MSG_VULN, param_name))
                            self.log(Vulnerability.MSG_PARAM_INJECT,
                                     self.MSG_VULN,
                                     evil_req.url,
                                     param_name)
                            if self.color:
                                self.log(Vulnerability.MSG_WITH_PARAMS,
                                         self.HTTP.encode(post_params)
                                         .replace(param_name + "=",
                                                  self.RED + param_name + self.STD + "="))
                            else:
                                self.log(Vulnerability.MSG_WITH_PARAMS,
                                         self.HTTP.encode(post_params))
                            self.log(Vulnerability.MSG_FROM, referer)
                            break

                        else:
                            if code == "500" and err500 == 0:
                                err500 = 1
                                self.logAnom(category=Anomaly.ERROR_500,
                                             level=Anomaly.HIGH_LEVEL,
                                             request=evil_req,
                                             parameter=param_name,
                                             info=Anomaly.MSG_PARAM_500.format(param_name))
                                self.log(Anomaly.MSG_500, evil_req.url)
                                self.log(Anomaly.MSG_WITH_PARAMS, self.HTTP.encode(post_params))
                                self.log(Anomaly.MSG_FROM, referer)
                param_list[i][1] = saved_value

    def loadRequire(self, obj=[]):
        self.deps = obj
        for x in self.deps:
            if x.name == "sql":
                self.excludedGET = x.vulnerableGET
                self.excludedPOST = x.vulnerablePOST
