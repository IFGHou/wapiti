import socket
from attack import Attack
from vulnerability import Vulnerability

# Wapiti v1.1.8-alpha - A web application vulnerability scanner
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

class CRLFAttack(Attack):
  """
  This class implements a CRLF attack
  """
  def __init__(self, HTTP, xmlRepGenerator):
    Attack.__init__(self, HTTP, xmlRepGenerator)

  # Won't work with PHP >= 4.4.2
  def attackGET(self, page, dict, attackedGET):
    payload="http://www.google.fr\r\nWapiti: version 1.1.7-alpha"
    if dict == {}:
      err = ""
      url = page+"?"+payload
      if url not in attackedGET:
        if self.verbose == 2:
          print "+ "+url
        try:
          if self.HTTP.send(url).getInfo().has_key('Wapiti'):
            self.reportGen.logVulnerability(Vulnerability.CRLF, Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              page, payload, err+" (QUERY_STRING)")
            print "CRLF Injection (QUERY_STRING) in", page
            print "\tEvil url:", url
        except socket.timeout:
          pass
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
            if self.HTTP.send(url).getInfo().has_key('Wapiti'):
              err = "CRLF Injection"
              if self.color == 0:
                self.reportGen.logVulnerability(Vulnerability.CRLF, Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                  page, self.HTTP.encode(tmp), err+" ("+k+")")
                print err, "("+k+") in", page
                print "\tEvil url:", url
              else:
                self.reportGen.logVulnerability(Vulnerability.CRLF, Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                  page, self.HTTP.encode(tmp).
                                  err+" : "+url.replace(k+"=", "\033[0;31m"+k+"\033[0;0m="))
                print err, ":", url.replace(k+"=", "\033[0;31m"+k+"\033[0;0m=")
          except socket.timeout:
            pass
          attackedGET.append(url)

