import socket
from attack import Attack
#import base
from vulnerability import Vulnerability
import httplib

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

class mod_crlf(Attack):
  """
  This class implements a CRLF attack
  """

  name = "crlf"

  def __init__(self, HTTP, xmlRepGenerator):
    Attack.__init__(self, HTTP, xmlRepGenerator)

  # Won't work with PHP >= 4.4.2
  def attackGET(self, page, dict, headers = {}):
    """This method performs the CRLF attack with method GET"""
    payload="http://www.google.fr\r\nWapiti: SVN version"
    if dict == {}:
      err = ""
      url = page + "?" + payload
      if url not in self.attackedGET:
        if self.verbose == 2:
          print "+ " + page + "?http://www.google.fr\\r\\nWapiti: SVN version"
        try:
          if self.HTTP.send(url).getInfo().has_key('wapiti'):
            self.reportGen.logVulnerability(Vulnerability.CRLF, Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              page, payload, err + " " + _("(QUERY_STRING)"))
            print _("CRLF Injection (QUERY_STRING) in"), page
            print "\t" + _("Evil url") + ":", url
        except socket.timeout:
          self.reportGen.logVulnerability(Vulnerability.RES_CONSUMPTION, Vulnerability.MEDIUM_LEVEL_VULNERABILITY,
                            page, payload, err + " " + _("(QUERY_STRING)"))
          print _("Timeout (QUERY_STRING) in"), page
          print "\t" + _("caused by") + ":", url
        except httplib.BadStatusLine:
          #print "Error: The server did not understand this request"
          pass
        self.attackedGET.append(url)
    else:
      for k in dict.keys():
        err = ""
        tmp = dict.copy()
        tmp[k] = payload
        url = page + "?" + self.HTTP.encode(tmp, headers["link_encoding"])
        if url not in self.attackedGET:
          if self.verbose == 2:
            print "+ " + url
          try:
            if self.HTTP.send(url).getInfo().has_key('wapiti'):
              err = _("CRLF Injection")
              self.reportGen.logVulnerability(Vulnerability.CRLF, Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                page, self.HTTP.encode(tmp, headers["link_encoding"]), err + " (" + k + ")")
              if self.color == 0:
                print err, "(" + k + ") " + _("in"), page
                print "\t" + _("Evil url") + ":", url
              else:
                print err, ":", url.replace(k + "=", self.RED + k + self.STD + "=")
          except socket.timeout:
            self.reportGen.logVulnerability(Vulnerability.RES_CONSUMPTION, Vulnerability.MEDIUM_LEVEL_VULNERABILITY,
                              page, self.HTTP.encode(tmp, headers["link_encoding"]), err + " (" + k + ")")
            print _("Timeout") + " (" + k + ") " + _("in"), page
            print "\t" + _("caused by") + ":", url
          except httplib.BadStatusLine:
            print _("Error: The server did not understand this request")
          self.attackedGET.append(url)

