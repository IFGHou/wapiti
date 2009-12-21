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
      return "MySQL Injection"
    if data.find("supplied argument is not a valid MySQL") > 0:
      return "MySQL Injection"
    if data.find("[Microsoft][ODBC Microsoft Access Driver]") >= 0:
      return "Access-Based SQL Injection"
    if data.find("[Microsoft][ODBC SQL Server Driver]") >= 0:
      return "MSSQL-Based Injection"
    if data.find('Microsoft OLE DB Provider for ODBC Drivers</font> <font size="2" face="Arial">error') >= 0:
      return "MSSQL-Based Injection"
    if data.find("Microsoft OLE DB Provider for ODBC Drivers") >= 0:
      return "MSSQL-Based Injection"
    if data.find("java.sql.SQLException: Syntax error or access violation") >= 0:
      return "Java.SQL Injection"
    if data.find("PostgreSQL query failed: ERROR: parser:") >= 0:
      return "PostgreSQL Injection"
    if data.find("XPathException") >= 0:
      return "XPath Injection"
    if data.find("supplied argument is not a valid ldap") >= 0 or data.find("javax.naming.NameNotFoundException") >= 0:
      return "LDAP Injection"
    if data.find("DB2 SQL error:") >= 0:
      return "DB2 Injection"
    if data.find("Dynamic SQL Error") >= 0:
      return "Interbase Injection"
    if data.find("Sybase message:") >= 0:
      return "Sybase Injection"
    return ""

  def setTimeout(self, timeout):
    self.TIME_TO_SLEEP = str(1 + int(timeout))

  def attackGET(self, page, dict, headers = {}):
    """This method performs the SQL Injection attack with method GET"""
    # about this payload : http://shiflett.org/blog/2006/jan/addslashes-versus-mysql-real-escape-string
    payload = "\xBF'\"("
    vuln_found = 0

    if dict == {}:
      err = ""
      payload = self.HTTP.quote(payload)
      url = page + "?" + payload
      if url not in self.attackedGET:
        if self.verbose == 2:
          print "+ " + url
        try:
          data, code = self.HTTP.send(url).getPageCode()
        except socket.timeout:
          # No timeout report here... launch blind sql detection later
          data = ""
          code = "408"
          err = ""
        else:
          err = self.__findPatternInResponse(data)
        if err != "":
          vuln_found += 1
          self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                            url, payload, err + " " + _("(QUERY_STRING)"))
          print err, _("(QUERY_STRING) in"), page
          print "\t" + _("Evil url") + ":", url

          self.vulnerableGET.append(page + "?" + "__PAYLOAD__")

        else:
          if code == "500":
            self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                            url, payload,
                                            VulDescrip.ERROR_500 + "<br />" + VulDescrip.ERROR_500_DESCRIPTION)
            print _("500 HTTP Error code with")
            print "\t" + _("Evil url") + ":", url
        self.attackedGET.append(url)
      else:
        return 1
    else:
      for k in dict.keys():
        err = ""
        tmp = dict.copy()
        tmp[k] = "__PAYLOAD__"
        url = page + "?" + self.HTTP.encode(tmp, headers["link_encoding"]).replace("__PAYLOAD__", self.HTTP.quote(payload))
        if url not in self.attackedGET:
          if self.verbose == 2:
            print "+ "+url
          try:
            data, code = self.HTTP.send(url).getPageCode()
          except socket.timeout:
            # No timeout report here... launch blind sql detection later
            data = ""
            code = "408"
            err = ""
          else:
            err = self.__findPatternInResponse(data)
          if err != "":
            vuln_found += 1
            self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                            url, self.HTTP.encode(tmp).replace("__PAYLOAD__", self.HTTP.quote(payload)),
                                            err + " (" + k + ")")
            if self.color == 0:
              print err, "(" + k + ") " + _("in"), page
              print "\t" + _("Evil url") + ":", url
            else:
              print err, ":", url.replace(k + "=", self.RED + k + self.STD + "=")

            tmp[k] = "__PAYLOAD__"
            self.vulnerableGET.append(page + "?" + self.HTTP.encode(tmp).replace("__PAYLOAD__", self.HTTP.quote(payload)))

          else:
            if code == "500":
              self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              url, self.HTTP.encode(tmp),
                                              VulDescrip.ERROR_500 + "<br />" + VulDescrip.ERROR_500_DESCRIPTION)
              print _("500 HTTP Error code with")
              print "\t" + _("Evil url") + ":", url
          self.attackedGET.append(url)
        else:
          return 1
    return vuln_found

  def attackPOST(self, form):
    """This method performs the SQL Injection attack with method POST"""
    payload = "\xbf'\"("
    page = form[0]
    dict = form[1]
    err = ""
    vuln_found = 0

    for k in dict.keys():
      tmp = dict.copy()
      tmp[k] = payload
      if (page, tmp) not in self.attackedPOST:
        headers = {"Accept": "text/plain"}
        if self.verbose == 2:
          print "+ " + page
          print "  ", tmp
        tmp[k] = "__PAYLOAD__"
        post_data = self.HTTP.encode(tmp, form[3]).replace("__PAYLOAD__",self.HTTP.quote(payload))
        try:
          data, code = self.HTTP.send(page, post_data, headers).getPageCode()
        except socket.timeout:
          # No timeout report here... launch blind sql detection later
          data = ""
          code = "408"
        else:
          err = self.__findPatternInResponse(data)
        if err != "":
          vuln_found += 1
          self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                          Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                          page, post_data,
                                          err + " " + _("coming from") + " " + form[2])
          print err, _("in"), page
          if self.color == 1:
            print "  " + _("with params") + " =", \
                post_data.replace(k + "=", self.RED + k + self.STD + "=")
          else:
            print "  " + _("with params") + " =", post_data
          print "  " + _("coming from"), form[2]

          self.vulnerablePOST.append((page, tmp))
          tmp[k] = payload

        else:
          if code == "500":
            self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                            page, post_data,
                                            _("500 HTTP Error code coming from") + " " + form[2] + "<br>"+
                                            VulDescrip.ERROR_500_DESCRIPTION)
            print _("500 HTTP Error code in"), page
            print "  " + _("with params") + " =", post_data
            print "  " + _("coming from"), form[2]
        self.attackedPOST.append((page, tmp))
      else:
        return 1
    return vuln_found

