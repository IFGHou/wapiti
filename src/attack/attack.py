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
from file.auxtext import AuxText

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

    CONFIG_DIR_NAME = "config/attacks"
    BASE_DIR = os.path.normpath(os.path.join(os.path.abspath(__file__),'../..'))
    CONFIG_DIR = BASE_DIR+"/"+CONFIG_DIR_NAME

    # Color codes
    STD = "\033[0;0m"
    RED = "\033[0;31m"

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

    def attackGET(self, page, dict, headers = {}):
      return

    def attackPOST(self, form):
      return

    def loadRequire(self, obj = []):
      self.deps = obj

    def attack(self, urls, forms):
      if self.doGET == True:
        for url, headers in urls.items():
          dictio = {}
          params = []
          page = url

          if url.find("?") >= 0:
            page = url.split('?')[0]
            query = url.split('?')[1]
            params = query.split('&')
            if query.find("=") >= 0:
              for param in params:
                dictio[param.split('=')[0]] = param.split('=')[1]

          if self.verbose == 1:
            print "+ " + _("attackGET") + " "+url
            if params != []:
              print "  ", params

          self.attackGET(page, dictio, headers)

      if self.doPOST == True:
        for form in forms:
          if form[1] != {}:
            self.attackPOST(form)
