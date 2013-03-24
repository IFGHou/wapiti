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
          if self.verbose == 2:
            print "+", url
          try:
            resp = self.HTTP.send(url, headers=headers)
            data, code = resp.getPageCode()
          except requests.exceptions.Timeout, e:
            self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              url,payload, _("Blind SQL Injection (QUERY_STRING)"),
                              e)
            print _("Blind SQL Injection (QUERY_STRING) in"), page
            print "  " + _("Evil url") + ":",url
            break
          else:
            if code == "500" and err500 == 0:
              err500 = 1
              self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              url, payload,
                                              VulDescrip.ERROR_500 + "\n" + VulDescrip.ERROR_500_DESCRIPTION,
                                              resp)
              print _("500 HTTP Error code with")
              print "  " + _("Evil url") + ":", url
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

            params_list[i][1] = self.HTTP.quote(payload.replace("__TIME__", self.TIME_TO_SLEEP))
            url = page + "?" + self.HTTP.encode(params_list)
            if self.verbose == 2:
              print "+", url
            try:
              resp = self.HTTP.send(url, headers=headers)
              data, code = resp.getPageCode()
            except requests.exceptions.Timeout, e:
              self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              url, self.HTTP.encode(params_list),
                                              _("Blind SQL Injection") + " (" + param_name + ")", e)
              if self.color == 0:
                print _("Blind SQL Injection") + " (" + param_name + ") " + _("in"), page
                print "  " + _("Evil url") + ":", url
              else:
                print _("Blind SQL Injection") + ":", url.replace(param_name + "=", self.RED + param_name + self.STD + "=")
              # One payload worked. Now jum to next field
              break
            else:
              if code == "500" and err500 == 0:
                err500 = 1
                self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                                url, self.HTTP.encode(params_list),
                                                VulDescrip.ERROR_500 + "\n" + VulDescrip.ERROR_500_DESCRIPTION,
                                                resp)
                print _("500 HTTP Error code with")
                print "  " + _("Evil url") + ":", url
        params_list[i][1] = saved_value

  def attackPOST(self, form):
    """This method performs the Blind SQL attack with method POST"""
    page = form.url

    # copies
    get_params  = form.get_params
    post_params = form.post_params
    file_params = form.file_params
    referer     = form.referer

    for param_list in [get_params, post_params, file_params]:
      for i in xrange(len(param_list)):
        saved_value = param_list[i][1]
        param_name = self.HTTP.quote(param_list[i][0])
        param_list[i][1] = "__SQL__"
        attack_pattern = HTTP.HTTPResource(form.path, method=form.method, get_params=get_params, post_params=post_params, file_params=file_params)

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
              print "+", evil_req
            try:
              resp = self.HTTP.send(evil_req)
              data, code = resp.getPageCode()
            except requests.exceptions.Timeout, e:
              # Timeout means time-based SQL injection
              self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              evil_req.url, self.HTTP.encode(post_params),
                                              _("Blind SQL Injection coming from") + " " + referer, 
                                              e)
              print _("Blind SQL Injection in"), evil_req.url
              if self.color == 1:
                print "  " + _("with params") + " =", \
                      self.HTTP.encode(post_params).replace(param_name + "=", self.RED + param_name + self.STD + "=")
              else:
                print "  " + _("with params") + " =", self.HTTP.encode(post_params)
              print "  " + _("coming from"), referer
              break

            else:
              if code == "500" and err500 == 0:
                err500 = 1
                self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                                evil_req.url, self.HTTP.encode(post_params),
                                                _("500 HTTP Error code coming from") + " " + referer + "\n"+
                                                VulDescrip.ERROR_500_DESCRIPTION, resp)
                print _("500 HTTP Error code in"), evil_req.url
                print "  " + _("with params") + " =", self.HTTP.encode(post_params)
                print "  " + _("coming from"), referer
        param_list[i][1] = saved_value

  def loadRequire(self, obj = []):
    self.deps = obj
    for x in self.deps:
      if x.name == "sql":
        self.excludedGET = x.vulnerableGET
        self.excludedPOST = x.vulnerablePOST

