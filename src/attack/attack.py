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

import os
import socket # for trapping socket.error
from file.auxtext import AuxText
import requests

class Attack:
    """
    This class represents an attack, it must be extended
    for any class which implements a new type of attack
    """
    verbose = 0
    color   = 0

    name = "attack"

    reportGen = None
    HTTP      = None
    auxText   = None

    doGET = True
    doPOST = True

    # List of modules (strs) that must be launched before the current module
    # Must be defined in the code of the module
    require = []
    # List of modules (objects) that must be launched before the current module
    # Must be left empty in the code
    deps = []

    # List of attack's url already launched in the current module
    attackedGET  = []
    attackedPOST = []

    vulnerableGET  = []
    vulnerablePOST = []

    CONFIG_DIR = ""
    if os.path.isdir("/usr/local/share/doc/packages/wapiti"):
        CONFIG_DIR = "/usr/local/share/doc/packages/wapiti/config/attacks"
    else:
      BASE_DIR = os.path.normpath(os.path.join(os.path.abspath(__file__),'../..'))
      CONFIG_DIR = BASE_DIR + "/" + "config/attacks"

    # Color codes
    STD = "\033[0;0m"
    RED = "\033[1;31m"
    YELLOW = "\033[1;33m"
    CYAN = "\033[1;36m"
    GB = "\033[0;30m\033[47m"

    allowed = ['php', 'html', 'htm', 'xml', 'xhtml', 'xht', 'xhtm',
              'asp', 'aspx', 'php3', 'php4', 'php5', 'txt', 'shtm',
              'shtml', 'phtm', 'phtml', 'jhtml', 'pl', 'jsp', 'cfm',
              'cfml', 'py']

    # The priority of the module, from 0 (first) to 10 (last). Default is 5
    PRIORITY = 5

    def __init__(self,HTTP,reportGen):
        self.HTTP = HTTP
        self.reportGen = reportGen
        self.auxText = AuxText()

    def setVerbose(self,verbose):
        self.verbose = verbose

    def setColor(self):
        self.color = 1

    def loadPayloads(self,fileName):
        """This method loads the payloads for an attack from the specified file"""
        return self.auxText.readLines(fileName)

    def attackGET(self, page, params_list, headers = {}):
      return

    def attackPOST(self, form):
      return

    def loadRequire(self, obj = []):
      self.deps = obj

    def attack(self, http_resources, forms):
      if self.doGET == True:
        for http_res in http_resources:
          url = http_res.url
#          params_list = []
#          params = []
#          page = url
#
#          if url.find("?") >= 0:
#            page = url.split('?')[0]
#            query = url.split('?')[1]
#            for param in query.split('&'):
#              if param.find("=") > 0:
#                params_list.append(param.split('=', 1))

          if self.verbose == 1:
            print "+ " + _("attackGET") + " "  + url

          try:
            self.attackGET(http_res)
          except socket.error, se:
            print 'error: %s while attacking %s' % (repr(str(se[0])), url)
          except requests.exceptions.Timeout, te:
            print 'error: timeout while attacking %s' % (url)
          #except Exception, e:
          #  print 'error: %s while attacking %s' % (repr(str(e[0])), url)

      if self.doPOST == True:
        for form in forms:
          try:
            self.attackPOST(form)
          except socket.error, se:
            print 'error: %s while attacking %s' % (repr(str(se[0])), url)
          except requests.exceptions.Timeout, te:
            print 'error: timeout while attacking %s' % (url)
       #   except Exception, e:
       #     print 'error: %s while attacking %s' % (repr(str(e[0])), url)
