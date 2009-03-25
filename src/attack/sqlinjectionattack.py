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

class SQLInjectionAttack(Attack):
  """
  This class implements an SQL Injection attack
  """

  CONFIG_FILE = "blindSQLPayloads.txt"
  blind_sql_payloads = []
  TIME_TO_SLEEP = 6

  def __init__(self,HTTP,xmlRepGenerator,timeout):
    Attack.__init__(self,HTTP,xmlRepGenerator)
    self.blind_sql_payloads = self.loadPayloads(self.CONFIG_DIR+"/"+self.CONFIG_FILE)
    self.TIME_TO_SLEEP = str(1 + int(timeout))

  def __findPatternInResponse(self,data):
    if data.find("You have an error in your SQL syntax")>=0:
      return "MySQL Injection"
    if data.find("supplied argument is not a valid MySQL")>0:
      return "MySQL Injection"
    if data.find("[Microsoft][ODBC Microsoft Access Driver]")>=0:
      return "Access-Based SQL Injection"
    if data.find("[Microsoft][ODBC SQL Server Driver]")>=0:
      return "MSSQL-Based Injection"
    if data.find('Microsoft OLE DB Provider for ODBC Drivers</font> <font size="2" face="Arial">error')>=0:
      return "MSSQL-Based Injection"
    if data.find("Microsoft OLE DB Provider for ODBC Drivers")>=0:
      return "MSSQL-Based Injection"
    if data.find("java.sql.SQLException: Syntax error or access violation")>=0:
      return "Java.SQL Injection"
    if data.find("PostgreSQL query failed: ERROR: parser:")>=0:
      return "PostgreSQL Injection"
    if data.find("XPathException")>=0:
      return "XPath Injection"
    if data.find("supplied argument is not a valid ldap")>=0 or data.find("javax.naming.NameNotFoundException")>=0:
      return "LDAP Injection"
    if data.find("DB2 SQL error:")>=0:
      return "DB2 Injection"
    if data.find("Dynamic SQL Error")>=0:
      return "Interbase Injection"
    if data.find("Sybase message:")>=0:
      return "Sybase Injection"
    return ""

  def attackGET(self,page,dict,attackedGET):
    # about this payload : http://shiflett.org/blog/2006/jan/addslashes-versus-mysql-real-escape-string
    payload = "\xBF'\"("
    vuln_found = 0

    if dict == {}:
      err = ""
      payload = self.HTTP.quote(payload)
      url = page+"?"+payload
      if url not in attackedGET:
        if self.verbose == 2:
          print "+ "+url
        try:
          data, code = self.HTTP.send(url).getPageCode()
        except socket.timeout:
          # No timeout report here... launch blind sql detection later
          data = ""
          code = 408
          err = ""
        else:
          err = self.__findPatternInResponse(data)
        if err != "":
          self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                            url, payload, err+" (QUERY_STRING)")
          print err, "(QUERY_STRING) in", page
          print "\tEvil url:", url
          vuln_found += 1
        else:
          if code == 500:
            self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                            url,payload,
                                            VulDescrip.ERROR_500+"<br>"+VulDescrip.ERROR_500_DESCRIPTION)
            print "500 HTTP Error code with"
            print "\tEvil url:", url
        attackedGET.append(url)
    else:
      for k in dict.keys():
        err = ""
        tmp = dict.copy()
        tmp[k] = payload
        url = page+"?"+self.HTTP.encode(tmp)
        if url not in attackedGET:
          if self.verbose == 2:
            print "+ "+url
          try:
            data, code = self.HTTP.send(url).getPageCode()
          except socket.timeout:
            # No timeout report here... launch blind sql detection later
            data = ""
            code = 408
            err = ""
          else:
            err = self.__findPatternInResponse(data)
          if err != "":
            if self.color == 0:
              self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              url, self.HTTP.encode(tmp),
                                              err+" ("+k+")")
              print err, "("+k+") in", page
              print "\tEvil url:", url
            else:
              self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              url,self.HTTP.encode(tmp),
                                              err+" : "+url.replace(k+"=", "\033[0;31m"+k+"\033[0;0m="))
              print err, ":", url.replace(k+"=", "\033[0;31m"+k+"\033[0;0m=")
            vuln_found += 1
          else:
            if code == 500:
              self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              url, self.HTTP.encode(tmp),
                                              VulDescrip.ERROR_500+"<br>"+VulDescrip.ERROR_500_DESCRIPTION)
              print "500 HTTP Error code with"
              print "\tEvil url:", url
          attackedGET.append(url)
    return vuln_found

  def attackPOST(self, form, attackedPOST):
    payload = "\xbf'\"("
    page = form[0]
    dict = form[1]
    err = ""
    vuln_found = 0

    for k in dict.keys():
      tmp = dict.copy()
      tmp[k] = payload
      if (page, tmp) not in attackedPOST:
        headers = {"Accept": "text/plain"}
        if self.verbose==2:
          print "+ "+page
          print "  ", tmp
        try:
          data, code = self.HTTP.send(page, self.HTTP.encode(tmp), headers).getPageCode()
        except socket.timeout:
          # No timeout report here... launch blind sql detection later
          data = ""
          code = 408
        else:
          err = self.__findPatternInResponse(data)
        if err != "":
          self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                          Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                          page, self.HTTP.encode(tmp),
                                          err+" coming from "+form[2])
          print err, "in", page
          print "  with params =", self.HTTP.encode(tmp)
          print "  coming from", form[2]
          vuln_found += 1
        else:
          if code == 500:
            self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                            page, self.HTTP.encode(tmp),
                                            "500 HTTP Error code coming from "+form[2]+"<br>"+
                                            VulDescrip.ERROR_500_DESCRIPTION)
            print "500 HTTP Error code in", page
            print "  with params =", self.HTTP.encode(tmp)
            print "  coming from", form[2]
        attackedPOST.append((page, tmp))
    return vuln_found

  # first implementations for blind sql injection...
  # must had this to Vulnerability type
  def blindGET(self, page, dict, attackedGET):
    if dict == {}:
      for payload in self.blind_sql_payloads:
        payload = self.HTTP.quote(payload.replace("__TIME__", self.TIME_TO_SLEEP))
        url = page+"?"+payload
        if url not in attackedGET:
          if self.verbose == 2:
            print "+ "+url
          try:
            data, code=self.HTTP.send(url).getPageCode()
          except socket.timeout:
            self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              url,payload, "Blind SQL Injection (QUERY_STRING)")
            print "Blind SQL Injection (QUERY_STRING) in", page
            print "\tEvil url:",url
            break
          else:
            if code == 500:
              self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              url, payload,
                                              VulDescrip.ERROR_500+"<br>"+VulDescrip.ERROR_500_DESCRIPTION)
              print "500 HTTP Error code with"
              print "\tEvil url:", url
          attackedGET.append(url)
    else:
      for k in dict.keys():
        tmp = dict.copy()
        for payload in self.blind_sql_payloads:
          tmp[k] = payload.replace("__TIME__", self.TIME_TO_SLEEP)
          url = page+"?"+self.HTTP.encode(tmp)
          if url not in attackedGET:
            if self.verbose == 2:
              print "+ "+url
            try:
              data, code = self.HTTP.send(url).getPageCode()
            except socket.timeout:
              if self.color == 0:
                self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                                url, self.HTTP.encode(tmp),
                                                "Blind SQL Injection ("+k+")")
                print "Blind SQL Injection ("+k+") in", page
                print "\tEvil url:", url
              else:
                self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                                url, self.HTTP.encode(tmp),
                                                "blind : "+url.replace(k+"=", "\033[0;31m"+k+"\033[0;0m="))
                print "Blind SQL Injection:", url.replace(k+"=", "\033[0;31m"+k+"\033[0;0m=")
              break # ok, one of the payloads worked
            else:
              if code == 500:
                self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                                url, self.HTTP.encode(tmp),
                                                VulDescrip.ERROR_500+"<br>"+VulDescrip.ERROR_500_DESCRIPTION)
                print "500 HTTP Error code with"
                print "\tEvil url:", url
            attackedGET.append(url)

  def blindPOST(self, form, attackedPOST):
    page = form[0]
    dict = form[1]
    for k in dict.keys():
      tmp = dict.copy()
      for payload in self.blind_sql_payloads:
        tmp[k] = payload.replace("__TIME__", self.TIME_TO_SLEEP)
        if (page, tmp) not in attackedPOST:
          headers = {"Accept": "text/plain"}
          if self.verbose == 2:
            print "+ "+page
            print "  ", tmp
          try:
            data, code = self.HTTP.send(page, self.HTTP.encode(tmp), headers).getPageCode()
          except socket.timeout:
            self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                            page, self.HTTP.encode(tmp),
                                            "Blind SQL Injection coming from "+form[2])
            print "Blind SQL Injection in", page
            print "  with params =", self.HTTP.encode(tmp)
            print "  coming from", form[2]
            break # ok, one of the payloads worked
          else:
            if code == 500:
              self.reportGen.logVulnerability(Vulnerability.BLIND_SQL_INJECTION,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              page, self.HTTP.encode(tmp),
                                              "500 HTTP Error code coming from "+form[2]+"<br>"+
                                              VulDescrip.ERROR_500_DESCRIPTION)
              print "500 HTTP Error code in", page
              print "  with params =", self.HTTP.encode(tmp)
              print "  coming from", form[2]
          attackedPOST.append((page, tmp))

