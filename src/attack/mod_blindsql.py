import socket
from attack import Attack
from vulnerability import Vulnerability
from vulnerabilitiesdescriptions import VulnerabilitiesDescriptions as VulDescrip
import requests
from copy import deepcopy

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
    headers = http_res.headers

    if not params_list:
      # Do not attack application-type files
      if not headers.has_key("content-type"):
        # Sometimes there's no content-type... so we rely on the document extension
        if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
          return
      elif headers["content-type"].find("text") == -1:
        return

      if page + "?__PAYLOAD__" in self.excludedGET:
        return

      err500 = 0
      for payload in self.blind_sql_payloads:
        payload = self.HTTP.quote(payload.replace("__TIME__", self.TIME_TO_SLEEP))
        url = page + "?__TIME__"
        if url not in self.attackedGET:
          self.attackedGET.append(url)
          url = page + "?" + payload
          if self.verbose == 2:
            print "+ " + url
          try:
            resp = self.HTTP.send(url)
            data, code = resp.getPageCode()
          #except socket.timeout:
          except requests.exceptions.Timeout, timeout:
            self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              url,payload, _("Blind SQL Injection (QUERY_STRING)"),
                              timeout)
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
        tmp = deepcopy(params_list)

        k = tmp[i][0]
        tmp[i][1] = "__PAYLOAD__"
        if page + "?" + self.HTTP.encode(tmp) in self.excludedGET:
          return

        tmp[i][1] = "__TIME__"
        url_to_log = page + "?" + self.HTTP.encode(tmp)

        err500 = 0
        for payload in self.blind_sql_payloads:

          if url_to_log not in self.attackedGET:
            tmp[i][1] = payload.replace("__TIME__", self.TIME_TO_SLEEP)
            url = page + "?" + self.HTTP.encode(tmp)
            if self.verbose == 2:
              print "+ " + url
            try:
              resp = self.HTTP.send(url)
              data, code = resp.getPageCode()
            #except socket.timeout:
            except requests.exceptions.Timeout, timeout:
              self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              url, self.HTTP.encode(tmp),
                                              _("Blind SQL Injection") + " (" + k + ")", timeout)
              if self.color == 0:
                print _("Blind SQL Injection") + " (" + k + ") " + _("in"), page
                print "  " + _("Evil url") + ":", url
              else:
                print _("Blind SQL Injection") + ":", url.replace(k + "=", self.RED + k + self.STD + "=")
              # ok, one of the payloads worked
              # log the url and exit
              self.attackedGET.append(url_to_log)
              break
            else:
              if code == "500" and err500 == 0:
                err500 = 1
                self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                                url, self.HTTP.encode(tmp),
                                                VulDescrip.ERROR_500 + "\n" + VulDescrip.ERROR_500_DESCRIPTION,
                                                resp)
                print _("500 HTTP Error code with")
                print "  " + _("Evil url") + ":", url

        # none of the payloads worked
        self.attackedGET.append(url_to_log)

  def attackPOST(self, form):
    """This method performs the Blind SQL attack with method POST"""
    page = form.url
    params_list = form.post_params

    for i in range(len(params_list)):
      tmp = deepcopy(params_list)
      k = tmp[i][0]

      tmp[i][1] = "__PAYLOAD__"
      if (page, tmp) in self.excludedPOST:
        return

      err500 = 0
      for payload in self.blind_sql_payloads:
        tmp[i][1] = "__TIME__"

        if (page, tmp) not in self.attackedPOST:
          tmp[i][1] = self.HTTP.quote(payload.replace("__TIME__", self.TIME_TO_SLEEP))

          headers = {"Accept": "text/plain"}
          if self.verbose == 2:
            print "+ " + page
            print "  ", tmp
          try:
            resp = self.HTTP.send(page, post_params = self.HTTP.encode(tmp), http_headers = headers)
            data,code = resp.getPageCode()
          #except socket.timeout:
          except requests.exceptions.Timeout, timeout:
            self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                            page, self.HTTP.encode(tmp),
                                            _("Blind SQL Injection coming from") + " " + form.referer, 
                                            timeout)
            print _("Blind SQL Injection in"), page
            if self.color == 1:
              print "  " + _("with params") + " =", \
                    self.HTTP.encode(tmp).replace(k + "=", self.RED + k + self.STD + "=")
            else:
              print "  " + _("with params") + " =", self.HTTP.encode(tmp)
            print "  " + _("coming from"), form.referer

            # one of the payloads worked. log the form and exit
            tmp[i][1] = "__TIME__"
            self.attackedPOST.append((page, tmp))
            break
          else:
            if code == "500" and err500 == 0:
              err500 = 1
              self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              page, self.HTTP.encode(tmp),
                                              _("500 HTTP Error code coming from") + " " + form.referer + "\n"+
                                              VulDescrip.ERROR_500_DESCRIPTION, resp)
              print _("500 HTTP Error code in"), page
              print "  " + _("with params") + " =", self.HTTP.encode(tmp)
              print "  " + _("coming from"), form.referer
      # none of the payloads worked. log the url and exit
      tmp[i][1] = "__TIME__"
      self.attackedPOST.append((page, tmp))

  def loadRequire(self, obj = []):
    self.deps = obj
    for x in self.deps:
      if x.name == "sql":
        self.excludedGET = x.vulnerableGET
        self.excludedPOST = x.vulnerablePOST

