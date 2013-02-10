import socket
import re
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

class mod_sql(Attack):
  """
  This class implements an SQL Injection attack
  """

  TIME_TO_SLEEP = 6
  name = "sql"

  def __init__(self, HTTP, xmlRepGenerator):
    Attack.__init__(self, HTTP, xmlRepGenerator)

  def __findPatternInResponse(self, data):
    if data.find("You have an error in your SQL syntax") >= 0:
      return _("MySQL Injection")
    if data.find("supplied argument is not a valid MySQL") > 0:
      return _("MySQL Injection")
    if data.find("[Microsoft][ODBC Microsoft Access Driver]") >= 0:
      return _("Access-Based SQL Injection")
    if data.find("[Microsoft][ODBC SQL Server Driver]") >= 0:
      return _("MSSQL-Based Injection")
    if data.find('Microsoft OLE DB Provider for ODBC Drivers</font> <font size="2" face="Arial">error') >= 0:
      return _("MSSQL-Based Injection")
    if data.find("Microsoft OLE DB Provider for ODBC Drivers") >= 0:
      return _("MSSQL-Based Injection")
    if data.find("java.sql.SQLException: Syntax error or access violation") >= 0:
      return _("Java.SQL Injection")
    if data.find("PostgreSQL query failed: ERROR: parser:") >= 0:
      return _("PostgreSQL Injection")
    if data.find("XPathException") >= 0:
      return _("XPath Injection")
    if data.find("supplied argument is not a valid ldap") >= 0 or data.find("javax.naming.NameNotFoundException") >= 0:
      return _("LDAP Injection")
    if data.find("DB2 SQL error:") >= 0:
      return _("DB2 Injection")
    if data.find("Dynamic SQL Error") >= 0:
      return _("Interbase Injection")
    if data.find("Sybase message:") >= 0:
      return _("Sybase Injection")
    if data.find("Unclosed quotation mark after the character string") >= 0:
      return _(".NET SQL Injection")

    #TODO: MS can also give some error codes like this: Microsoft SQL Native Client error '80040e14'
    ora_test = re.search("ORA-[0-9]{4,}", data)
    if ora_test != None:
      return _("Oracle Injection") + " " + ora_test.group(0)

    return ""

  def setTimeout(self, timeout):
    self.TIME_TO_SLEEP = str(1 + int(timeout))

  def attackGET(self, page, params_list, headers = {}):
    """This method performs the SQL Injection attack with method GET"""
    # about this payload : http://shiflett.org/blog/2006/jan/addslashes-versus-mysql-real-escape-string
    payload = "\xBF'\"("
    vuln_found = 0

    if not params_list:
      # Do not attack application-type files
      if not headers.has_key("content-type"):
        # Sometimes there's no content-type... so we rely on the document extension
        if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
          return
      elif headers["content-type"].find("text") == -1:
        return

      err = ""
      payload = self.HTTP.quote(payload)
      url = page + "?" + payload
      if url not in self.attackedGET:
        if self.verbose == 2:
          print "+ " + url
        try:
          resp = self.HTTP.send(url)
          data, code = resp.getPageCode()
        except requests.exceptions.Timeout, timeout:
          # No timeout report here... launch blind sql detection later
          data = ""
          code = "408"
          err = ""
          resp = timeout
        else:
          err = self.__findPatternInResponse(data)
        if err != "":
          vuln_found += 1
          self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                            url, payload, err + " " + _("(QUERY_STRING)"),
                            resp)
          print err, _("(QUERY_STRING) in"), page
          print "  " + _("Evil url") + ":", url

          self.vulnerableGET.append(page + "?" + "__PAYLOAD__")

        else:
          if code == "500":
            self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                            url, payload,
                                            VulDescrip.ERROR_500 + "\n" + VulDescrip.ERROR_500_DESCRIPTION,
                                            resp)
            print _("500 HTTP Error code with")
            print "  " + _("Evil url") + ":", url
        self.attackedGET.append(url)
      else:
        return 1
    else:
      for i in range(len(params_list)):
        err = ""
        tmp = deepcopy(params_list)
        k = tmp[i][0]
        tmp[i][1] = "__PAYLOAD__"
        url = page + "?" + self.HTTP.encode(tmp, headers["link_encoding"]).replace("__PAYLOAD__", self.HTTP.quote(payload))
        if url not in self.attackedGET:
          if self.verbose == 2:
            print "+ "+url
          try:
            resp = self.HTTP.send(url)
            data, code = resp.getPageCode()
          except requests.exceptions.Timeout, timeout:
            # No timeout report here... launch blind sql detection later
            data = ""
            code = "408"
            err = ""
            resp = timeout
          else:
            err = self.__findPatternInResponse(data)
          if err != "":
            vuln_found += 1
            self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                            url, self.HTTP.encode(tmp, headers["link_encoding"]).replace("__PAYLOAD__", self.HTTP.quote(payload)),
                                            err + " (" + k + ")", resp)
            if self.color == 0:
              print err, "(" + k + ") " + _("in"), page
              print "  " + _("Evil url") + ":", url
            else:
              print err, ":", url.replace(k + "=", self.RED + k + self.STD + "=")

            tmp[i][1] = "__PAYLOAD__"
            self.vulnerableGET.append(page + "?" + self.HTTP.encode(tmp, headers["link_encoding"]))

          else:
            if code == "500":
              self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              url, self.HTTP.encode(tmp, headers["link_encoding"]).replace("__PAYLOAD__", self.HTTP.quote(payload)),
                                              VulDescrip.ERROR_500 + "\n" + VulDescrip.ERROR_500_DESCRIPTION,
                                              resp)
              print _("500 HTTP Error code with")
              print "  " + _("Evil url") + ":", url
          self.attackedGET.append(url)
        else:
          return 1
    return vuln_found

  def attackPOST(self, form):
    """This method performs the SQL Injection attack with method POST"""
    payload = "\xbf'\"("
    page = form[0]
    params_list = form[1]
    err = ""
    vuln_found = 0

    for i in range(len(params_list)):
      tmp = deepcopy(params_list)
      tmp[i][1] = "__PAYLOAD__"
      k = tmp[i][0]

      if (page, tmp) not in self.attackedPOST:
        headers = {"accept": "text/plain"}
        if self.verbose == 2:
          print "+ " + page
          tmp[i][1] = payload
          print "  ", tmp
          tmp[i][1] = "__PAYLOAD__"
        post_data = self.HTTP.encode(tmp, form[3]).replace("__PAYLOAD__",self.HTTP.quote(payload))
        try:
          resp = self.HTTP.send(page, post_data = post_data, http_headers = headers)
          data, code = resp.getPageCode()
        except requests.exceptions.Timeout, timeout:
          # No timeout report here... launch blind sql detection later
          data = ""
          code = "408"
          resp = timeout
        else:
          err = self.__findPatternInResponse(data)
        if err != "":
          vuln_found += 1
          self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                          Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                          page, post_data,
                                          err + " " + _("coming from") + " " + form[2],
                                          resp)
          print err, _("in"), page
          if self.color == 1:
            print "  " + _("with params") + " =", \
                post_data.replace(k + "=", self.RED + k + self.STD + "=")
          else:
            print "  " + _("with params") + " =", post_data
          print "  " + _("coming from"), form[2]

          self.vulnerablePOST.append((page, tmp))

        else:
          if code == "500":
            self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                            page, post_data,
                                            _("500 HTTP Error code coming from") + " " + form[2] + "\n"+
                                            VulDescrip.ERROR_500_DESCRIPTION,
                                            resp)
            print _("500 HTTP Error code in"), page
            print "  " + _("with params") + " =", post_data
            print "  " + _("coming from"), form[2]
        self.attackedPOST.append((page, tmp))
      else:
        return 1
    return vuln_found

