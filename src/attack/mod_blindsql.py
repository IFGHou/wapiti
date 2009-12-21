import socket
from attack import Attack
from vulnerability import Vulnerability
from vulnerabilitiesdescriptions import VulnerabilitiesDescriptions as VulDescrip

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
  def attackGET(self, page, dict, headers = {}):
    """This method performs the Blind SQL attack with method GET"""
    if dict == {}:

      if page + "?__PAYLOAD__" in self.excludedGET:
        return

      for payload in self.blind_sql_payloads:
        payload = self.HTTP.quote(payload.replace("__TIME__", self.TIME_TO_SLEEP))
        url = page + "?__TIME__"
        if url not in self.attackedGET:
          self.attackedGET.append(url)
          url = page + "?" + payload
          if self.verbose == 2:
            print "+ " + url
          try:
            data, code = self.HTTP.send(url).getPageCode()
          except socket.timeout:
            self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              url,payload, _("Blind SQL Injection (QUERY_STRING)"))
            print _("Blind SQL Injection (QUERY_STRING) in"), page
            print "\t" + _("Evil url") + ":",url
            break
          else:
            if code == "500":
              self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              url, payload,
                                              VulDescrip.ERROR_500+"<br>"+VulDescrip.ERROR_500_DESCRIPTION)
              print _("500 HTTP Error code with")
              print "\t" + _("Evil url") + ":", url
    else:
      for k in dict.keys():
        tmp = dict.copy()

        tmp[k] = "__PAYLOAD__"
        if page + "?" + self.HTTP.encode(tmp, headers["link_encoding"]) in self.excludedGET:
          return

        tmp[k] = "__TIME__"
        url_to_log = page + "?" + self.HTTP.encode(tmp, headers["link_encoding"])

        for payload in self.blind_sql_payloads:

          if url_to_log not in self.attackedGET:
            tmp[k] = payload.replace("__TIME__", self.TIME_TO_SLEEP)
            url = page + "?" + self.HTTP.encode(tmp, headers["link_encoding"])
            if self.verbose == 2:
              print "+ " + url
            try:
              data, code = self.HTTP.send(url).getPageCode()
            except socket.timeout:
              self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              url, self.HTTP.encode(tmp, headers["link_encoding"]),
                                              _("Blind SQL Injection") + " (" + k + ")")
              if self.color == 0:
                print _("Blind SQL Injection") + " (" + k + ") " + _("in"), page
                print "\t" + _("Evil url") + ":", url
              else:
                print _("Blind SQL Injection") + ":", url.replace(k + "=", self.RED + k + self.STD + "=")
              # ok, one of the payloads worked
              # log the url and exit
              self.attackedGET.append(url_to_log)
              break
            else:
              if code == "500":
                self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                                url, self.HTTP.encode(tmp, headers["link_encoding"]),
                                                VulDescrip.ERROR_500 + "<br />" + VulDescrip.ERROR_500_DESCRIPTION)
                print _("500 HTTP Error code with")
                print "\t" + _("Evil url") + ":", url

        # none of the payloads worked
        self.attackedGET.append(url_to_log)

  def attackPOST(self, form):
    """This method performs the Blind SQL attack with method POST"""
    page = form[0]
    dict = form[1]
    for k in dict.keys():
      tmp = dict.copy()

      tmp[k] = "__PAYLOAD__"
      if (page, tmp) in self.excludedPOST:
        return

      for payload in self.blind_sql_payloads:
        tmp[k] = "__TIME__"

        if (page, tmp) not in self.attackedPOST:
          tmp[k] = payload.replace("__TIME__", self.TIME_TO_SLEEP)

          headers = {"Accept": "text/plain"}
          if self.verbose == 2:
            print "+ " + page
            print "  ", tmp
          try:
            data, code = self.HTTP.send(page, self.HTTP.encode(tmp, form[3]), headers).getPageCode()
          except socket.timeout:
            self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                            page, self.HTTP.encode(tmp, form[3]),
                                            _("Blind SQL Injection coming from") + " "+form[2])
            print _("Blind SQL Injection in"), page
            if self.color == 1:
              print "  " + _("with params") + " =", \
                    self.HTTP.encode(tmp, form[3]).replace(k + "=", self.RED + k + self.STD + "=")
            else:
              print "  " + _("with params") + " =", self.HTTP.encode(tmp, form[3])
            print "  " + _("coming from"), form[2]

            # one of the payloads worked. log the form and exit
            tmp[k] = "__TIME__"
            self.attackedPOST.append((page, tmp))
            break
          else:
            if code == "500":
              self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              page, self.HTTP.encode(tmp, form[3]),
                                              _("500 HTTP Error code coming from") + " " + form[2] + "<br>"+
                                              VulDescrip.ERROR_500_DESCRIPTION)
              print _("500 HTTP Error code in"), page
              print "  " + _("with params") + " =", self.HTTP.encode(tmp, form[3])
              print "  " + _("coming from"), form[2]
      # none of the payloads worked. log the url and exit
      tmp[k] = "__TIME__"
      self.attackedPOST.append((page, tmp))

    def loadRequire(self, obj = []):
      self.deps = obj
      for x in self.deps:
        if x.name == "sql":
          self.excludedGET = x.vulnerableGET
          self.excludedPOST = x.vulnerablePOST

