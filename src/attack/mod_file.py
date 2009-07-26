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
      ("<b>Warning:</b>  highlight_file(",      "highlight_file()")
      ]

  def __init__(self, HTTP, xmlRepGenerator):
    Attack.__init__(self, HTTP, xmlRepGenerator)
    self.payloads = self.loadPayloads(self.CONFIG_DIR+"/"+self.CONFIG_FILE)

  def __findPatternInResponse(self, data, inc, warn):
    """This method searches patterns in the response from the server"""
    err = ""
    if data.find("root:x:0:0")>=0:
      err = "Unix include/fread"
      inc = 1
    if data.find("[boot loader]")>=0:
      err = "Windows include/fread"
      inc = 1
    if data.find("<title>Google</title>")>0:
      err = "Remote include"
      inc = 1
    for pattern, funcname in self.warning_messages:
      if data.find(pattern) >= 0 and warn == 0:
        err = "Warning " + funcname
        warn = 1
        break
    return err, inc, warn

  def attackGET(self, page, dict, attackedGET):
    """This method performs the file handling attack with method GET"""
    if dict == {}:
      warn = 0
      inc = 0
      err500 = 0
      for payload in self.payloads:
        err = ""
        url = page+"?"+self.HTTP.quote(payload)
        if url not in attackedGET:
          if self.verbose == 2:
            print "+ "+url
          attackedGET.append(url)
          if inc == 1: continue
          try:
            data, code = self.HTTP.send(url).getPageCode()
          except socket.timeout:
            data = ""
            code = "408"
            err = ""
            self.reportGen.logVulnerability(Vulnerability.RES_CONSUMPTION,
                              Vulnerability.MEDIUM_LEVEL_VULNERABILITY,
                              url, self.HTTP.quote(payload),
                              _("Timeout (QUERY_STRING) in")+" "+str(page))
            print _("Timeout (QUERY_STRING) in"), page
            print "\t"+_("caused by")+":", url
          else:
            err,inc,warn = self.__findPatternInResponse(data,inc,warn)
          if err != "":
            self.reportGen.logVulnerability(Vulnerability.FILE_HANDLING,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              url, self.HTTP.quote(payload),
                              str(err)+" "+_("(QUERY_STRING) in")+" "+str(page))
            print err, _("(QUERY_STRING) in"), page
            print "\t"+_("Evil url")+":", url
          else:
            if code == "500" and err500 == 0:
              err500 = 1
              self.reportGen.logVulnerability(Vulnerability.FILE_HANDLING,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                url, self.HTTP.quote(payload),
                                VulDescrip.ERROR_500+"<br>"+VulDescrip.ERROR_500_DESCRIPTION)
              print _("500 HTTP Error code with")
              print "\t"+_("Evil url")+":", url
    for k in dict.keys():
      warn = 0
      inc = 0
      err500 = 0
      for payload in self.payloads:
        err = ""
        tmp = dict.copy()
        tmp[k] = payload
        url = page+"?"+self.HTTP.encode(tmp)
        if url not in attackedGET:
          if self.verbose == 2:
            print "+ "+url
          attackedGET.append(url)
          if inc == 1: continue
          try:
            data, code = self.HTTP.send(url).getPageCode()
          except socket.timeout:
            data = ""
            code = "408"
            err = ""
            self.reportGen.logVulnerability(Vulnerability.RES_CONSUMPTION,
                              Vulnerability.MEDIUM_LEVEL_VULNERABILITY,
                              url,self.HTTP.encode(tmp), err+" ("+k+")")
            print _("Timeout")+" ("+k+") "+_("in"), page
            print "\t"+_("caused by")+":", url
          else:
            err, inc, warn = self.__findPatternInResponse(data,inc,warn)
          if err != "":
            if self.color == 0:
              self.reportGen.logVulnerability(Vulnerability.FILE_HANDLING,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.encode(tmp), err+" ("+k+")")
              print err, "("+k+") "+_("in"), page
              print "\t"+_("Evil url")+":", url
            else:
              self.reportGen.logVulnerability(Vulnerability.FILE_HANDLING,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY,url, self.HTTP.encode(tmp),
                                err+" : "+url.replace(k+"=", "\033[0;31m"+k+"\033[0;0m="))
              print err, ":", url.replace(k+"=", "\033[0;31m"+k+"\033[0;0m=")
          else:
            if code == "500" and err500 == 0:
              err500 = 1
              self.reportGen.logVulnerability(Vulnerability.FILE_HANDLING,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                url, self.HTTP.encode(tmp),
                                VulDescrip.ERROR_500+"<br>"+VulDescrip.ERROR_500_DESCRIPTION)
              print _("500 HTTP Error code with")
              print "\t"+_("Evil url")+":", url

  def attackPOST(self,form,attackedPOST):
    """This method performs the file handling attack with method POST"""
    page = form[0]
    dict = form[1]
    err = ""
    for payload in self.payloads:
      warn = 0
      inc = 0
      err500 = 0
      for k in dict.keys():
        tmp = dict.copy()
        tmp[k] = payload
        if (page, tmp) not in attackedPOST:
          attackedPOST.append((page, tmp))
          if inc == 1: continue
          headers = {"Accept": "text/plain"}
          if self.verbose == 2:
            print "+ "+page
            print "  ", tmp
          try:
            data, code = self.HTTP.send(page, self.HTTP.encode(tmp), headers).getPageCode()
          except socket.timeout:
            data = ""
            code = "408"
            self.reportGen.logVulnerability(Vulnerability.RES_CONSUMPTION,
                              Vulnerability.MEDIUM_LEVEL_VULNERABILITY,
                              page, self.HTTP.encode(tmp),
                              _("Timeout coming from")+" "+form[2])
            print _("Timeout in"), page
            print "  "+_("with params")+" =", self.HTTP.encode(tmp)
            print "  "+_("coming from"), form[2]
          else:
            err, inc, warn = self.__findPatternInResponse(data, inc, warn)
          if err != "":
            self.reportGen.logVulnerability(Vulnerability.FILE_HANDLING,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              page, self.HTTP.encode(tmp),
                              err+" "+_("coming from")+" "+form[2])
            print err, _("in"), page
            print "  "+_("with params")+" =", self.HTTP.encode(tmp)
            print "  "+_("coming from"), form[2]
          else:
            if code == "500" and err500 == 0:
              err500 = 1
              self.reportGen.logVulnerability(Vulnerability.FILE_HANDLING,
                                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                              page, self.HTTP.encode(tmp),
                                              _("500 HTTP Error code coming from")+" "+form[2]+"<br>"+
                                              VulDescrip.ERROR_500_DESCRIPTION)
              print _("500 HTTP Error code in"),page
              print "  "+_("with params")+" =", self.HTTP.encode(tmp)
              print "  "+_("coming from"), form[2]

