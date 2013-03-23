#!/usr/bin/env python
#
# Authors:
# Anthony DUBOCAGE
# Guillaume TRANCHANT
# Gregory FONTAINE

import BeautifulSoup
from attack import Attack
from vulnerability import Vulnerability
from vulnerabilitiesdescriptions import VulnerabilitiesDescriptions as VulDescrip
import socket
from net import HTTP

class mod_backup(Attack):
  """
  This class implements a "backup attack"
  """

  payloads = []
  CONFIG_FILE = "backupPayloads.txt"

  name = "backup"

  doGET = False
  doPOST = False

  def __init__(self, HTTP, xmlRepGenerator):
    Attack.__init__(self, HTTP, xmlRepGenerator)
    self.payloads = self.loadPayloads(self.CONFIG_DIR+"/"+self.CONFIG_FILE)


  def __returnErrorByCode(self, code):
    err = ""
    if code == 404:
      err = "Not found"

    if 100 <= code < 300:
      err = "ok"

    return err


  def attackGET(self, http_res):

    page = http_res.path
    params_list = http_res.get_params
    headers = http_res.headers

    # Do not attack application-type files
    if not "content-type" in headers:
      # Sometimes there's no content-type... so we rely on the document extension
      if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
        return
    elif not "text" in headers["content-type"]:
      return

    for k in self.payloads:
      url = page + k
      
      if self.verbose == 2:
        print "+", url

      if url not in self.attackedGET:
        self.attackedGET.append(url)
        try:
          resp = self.HTTP.send(url)
          data, code = resp.getPageCode()
          err = self.__returnErrorByCode(code)
          if err == "ok":
            if self.color == 1:
              print self.RED + _("Found backup file !") + self.STD
              print self.RED + "    -> " + url + self.STD
            else:
              print " +", _("Found backup file !")
              print "   ->", url
            self.reportGen.logVulnerability(Vulnerability.BACKUP,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              url, "", _("Backup file found for") + " " + page, resp)
            
        except socket.timeout:
          data = ""
          break

