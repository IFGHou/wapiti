import socket
import re
from attack import Attack
from vulnerability import Vulnerability
from vulnerabilitiesdescriptions import VulnerabilitiesDescriptions as VulDescrip
import requests
from copy import deepcopy
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

  def attackGET(self, http_res):
    """This method performs the SQL Injection attack with method GET"""
    page = http_res.path
    params_list = http_res.get_params
    headers = http_res.headers

    # about this payload : http://shiflett.org/blog/2006/jan/addslashes-versus-mysql-real-escape-string
    payload = "\xBF'\"("
    vuln_found = 0

    if not params_list:
      # Do not attack application-type files
      if not headers.has_key("content-type"):
        # Sometimes there's no content-type... so we rely on the document extension
        if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
          return
      elif not "text" in headers["content-type"]:
        return

      err = ""
      payload = self.HTTP.quote(payload)
      url = page + "?" + payload
      if url not in self.attackedGET:
        if self.verbose == 2:
          print "+", url
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
        k = params_list[i][0]
        saved_value = params_list[i][1]
        params_list[i][1] = "__SQL__"
        url = page + "?" + self.HTTP.encode(params_list)
        if url not in self.attackedGET:
          self.attackedGET.append(url)

          params_list[i][1] = self.HTTP.quote(payload)
          url = page + "?" + self.HTTP.encode(params_list)

          if self.verbose == 2:
            print "+", url
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
            self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                            url, self.HTTP.encode(params_list).replace("__PAYLOAD__", self.HTTP.quote(payload)),
                                            err + " (" + k + ")", resp)
            if self.color == 0:
              print err, "(" + k + ") " + _("in"), page
              print "  " + _("Evil url") + ":", url
            else:
              print err, ":", url.replace(k + "=", self.RED + k + self.STD + "=")
            break

          elif code == "500":
              self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              url, self.HTTP.encode(params_list).replace("__PAYLOAD__", self.HTTP.quote(payload)),
                                              VulDescrip.ERROR_500 + "\n" + VulDescrip.ERROR_500_DESCRIPTION,
                                              resp)
              print _("500 HTTP Error code with")
              print "  " + _("Evil url") + ":", url
        params_list[i][1] = saved_value

  def attackPOST(self, form):
    """This method performs the SQL Injection attack with method POST"""
    payload = "\xbf'\"("
    page = form.url
    err = ""

    # copies
    get_params  = form.get_params
    post_params = form.post_params
    file_params = form.file_params

    for param_list in [get_params, post_params, file_params]:
      for i in xrange(len(param_list)):
        saved_value = param_list[i][1]

        param_list[i][1] = "__SQL__"
        k = param_list[i][0]
        attack_pattern = HTTP.HTTPResource(form.path, method=form.method, get_params=get_params, post_params=post_params, file_params=file_params)
        if attack_pattern not in self.attackedPOST:
          self.attackedPOST.append(attack_pattern)

          param_list[i][1] = payload
          evil_req = HTTP.HTTPResource(form.path, method=form.method, get_params=get_params, post_params=post_params, file_params=file_params)
          if self.verbose == 2:
            print "+", evil_req

          try:
            resp = self.HTTP.send(evil_req)
            data, code = resp.getPageCode()
          except requests.exceptions.Timeout, timeout:
            # No timeout report here... launch blind sql detection later
            data = ""
            code = "408"
            resp = timeout
          else:
            err = self.__findPatternInResponse(data)
          if err != "":
            self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                            evil_req.url, self.HTTP.encode(post_params),
                                            err + " " + _("coming from") + " " + form.referer,
                                            resp)
            print err, _("in"), evil_req.url
            if self.color == 1:
              print "  " + _("with params") + " =", \
                  self.HTTP.encode(post_params).replace(k + "=", self.RED + k + self.STD + "=")
            else:
              print "  " + _("with params") + " =", self.HTTP.encode(post_params)
            print "  " + _("coming from"), form.referer
            break

          else:
            if code == "500":
              self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              evil_req.url, self.HTTP.encode(post_params),
                                              _("500 HTTP Error code coming from") + " " + form.referer + "\n"+
                                              VulDescrip.ERROR_500_DESCRIPTION,
                                              resp)
              print _("500 HTTP Error code in"), evil_req.url
              print "  " + _("with params") + " =", self.HTTP.encode(post_params)
              print "  " + _("coming from"), form.referer

        param_list[i][1] = saved_value

