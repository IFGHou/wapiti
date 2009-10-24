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

class mod_exec(Attack):
  """
  This class implements a command execution attack
  """

  CONFIG_FILE = "execPayloads.txt"

  name = "exec"

  def __init__(self, HTTP, xmlRepGenerator):
    Attack.__init__(self, HTTP, xmlRepGenerator)
    self.payloads = self.loadPayloads(self.CONFIG_DIR + "/" + self.CONFIG_FILE)

  def __findPatternInResponse(self, data, cmd, warn):
    err = ""
    if data.find("eval()'d code</b> on line <b>") >= 0 and warn == 0:
      err = "Warning eval()"
      warn = 1
    if data.find("PATH=") >= 0 and data.find("PWD=") >= 0:
      err = "Command execution"
      cmd = 1
    if data.find("Cannot execute a blank command in") >= 0 and warn == 0:
      err = "Warning exec"
      warn = 1
    if data.find("Fatal error</b>:  preg_replace") >= 0 and warn == 0:
      err = "preg_replace injection"
      warn = 1
    return err, cmd, warn

  def attackGET(self, page, dict, headers = {}):
    """This method performs the command execution with method GET"""
    if dict == {}:
      warn = 0
      cmd = 0
      err500 = 0
      for payload in self.payloads:
        err = ""
        url = page + "?" + self.HTTP.quote(payload)
        if url not in self.attackedGET:
          if self.verbose == 2:
            print "+ " + url
          self.attackedGET.append(url)
          if cmd == 1: continue
          try:
            data, code = self.HTTP.send(url).getPageCode()
          except socket.timeout:
            data = ""
            code = "408"
            err = ""
            print _("Timeout in"), page
            print "\t" + _("caused by") + ":", url
            self.reportGen.logVulnerability(Vulnerability.RES_CONSUMPTION,
                                            Vulnerability.MEDIUM_LEVEL_VULNERABILITY,
                                            url, self.HTTP.quote(payload), err+" "+_("(QUERY_STRING)"))
          else: 
            err, cmd, warn = self.__findPatternInResponse(data, cmd, warn)
          if err != "":
            self.reportGen.logVulnerability(Vulnerability.EXEC,
                                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                            url, self.HTTP.quote(payload), err+" "+_("(QUERY_STRING)"))
            print err, _("(QUERY_STRING) in"), page
            print "\t" + _("Evil url") + ":", url
          else:
            if code == "500" and err500 == 0:
              err500 = 1
              self.reportGen.logVulnerability(Vulnerability.EXEC,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              url, self.HTTP.quote(payload),
                                              VulDescrip.ERROR_500+"<br>"+VulDescrip.ERROR_500_DESCRIPTION)
              print _("500 HTTP Error code with")
              print "\t" + _("Evil url") + ":", url
    for k in dict.keys():
      warn = 0
      cmd = 0
      err500 = 0
      for payload in self.payloads:
        err = ""
        tmp = dict.copy()
        tmp[k] = payload
        url = page + "?" + self.HTTP.encode(tmp)
        if url not in self.attackedGET:
          if self.verbose == 2:
            print "+ " + url
          self.attackedGET.append(url)
          if cmd == 1: continue
          try:
            data, code = self.HTTP.send(url).getPageCode()
          except socket.timeout:
            data = ""
            code = "408"
            err = ""
            print _("Timeout") + " (" + k + ") " + _("in"), page
            print "\t" + _("caused by") + ":", url
            self.reportGen.logVulnerability(Vulnerability.RES_CONSUMPTION,
                                            Vulnerability.MEDIUM_LEVEL_VULNERABILITY,
                                            url, self.HTTP.encode(tmp), err+" ("+k+")")
          else:
            err, cmd, warn = self.__findPatternInResponse(data, cmd, warn)
          if err != "":
            self.reportGen.logVulnerability(Vulnerability.EXEC,
                                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                            url, self.HTTP.encode(tmp), err+" ("+k+")")
            if self.color == 0:
              print err, "(" + k + ") " + _("in"), page
              print "\t" + _("Evil url") + ":", url
            else:
              print err, ":", url.replace(k + "=", self.RED + k + self.STD + "=")
          else:
            if code == "500" and err500 == 0:
              err500 = 1
              self.reportGen.logVulnerability(Vulnerability.EXEC,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              url, self.HTTP.encode(tmp),
                                              VulDescrip.ERROR_500 + "<br />" + VulDescrip.ERROR_500_DESCRIPTION)
              print _("500 HTTP Error code with")
              print "\t" + _("Evil url") + ":", url

  def attackPOST(self, form):
    """This method performs the command execution with method POST"""
    page = form[0]
    dict = form[1]
    err = ""
    for payload in self.payloads:
      warn = 0
      cmd = 0
      err500 = 0
      for k in dict.keys():
        tmp = dict.copy()
        tmp[k] = payload
        if (page, tmp) not in self.attackedPOST:
          self.attackedPOST.append((page, tmp))
          if cmd == 1: continue
          headers = {"Accept": "text/plain"}
          if self.verbose == 2:
            print "+ " + page
            print "  ", tmp
          try:
            data, code = self.HTTP.send(page, self.HTTP.encode(tmp), headers).getPageCode()
          except socket.timeout:
            data = ""
            code = "408"
            print _("Timeout in"), page
            print "  " + _("with params") + " =", self.HTTP.encode(tmp)
            print "  " + _("coming from"), form[2]
            self.reportGen.logVulnerability(Vulnerability.RES_CONSUMPTION,
                                            Vulnerability.MEDIUM_LEVEL_VULNERABILITY,
                                            page, self.HTTP.encode(tmp),
                                            _("Timeout coming from") + " " + form[2])
          else:
            err, cmd, warn = self.__findPatternInResponse(data, cmd, warn)

          if err != "":
            self.reportGen.logVulnerability(Vulnerability.EXEC,
                                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                            page, self.HTTP.encode(tmp),
                                            err + " " + _("coming from") + " " + form[2])
            print err, _("in"), page
            if self.color == 1:
              print "  " + _("with params") + " =", \
                  self.HTTP.encode(tmp).replace(k + "=", self.RED + k + self.STD + "=")
            else:
              print "  " + _("with params") + " =", self.HTTP.encode(tmp)
            print "  " + _("coming from"), form[2]

          else:
            if code == "500" and err500 == 0:
              err500 = 1
              self.reportGen.logVulnerability(Vulnerability.EXEC,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              page, self.HTTP.encode(tmp),
                                              _("500 HTTP Error code coming from")+" "+form[2]+"<br>"+
                                              VulDescrip.ERROR_500_DESCRIPTION)
              print _("500 HTTP Error code in"), page
              print "  " + _("with params") + " =", self.HTTP.encode(tmp)
              print "  " + _("coming from"), form[2]

