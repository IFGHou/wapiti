#!/usr/bin/env python
#
# Authors:
# Anthony DUBOCAGE
# Guillaume TRANCHANT
# Gregory FONTAINE

from net import BeautifulSoup
from attack import Attack
from vulnerability import Vulnerability
from vulnerabilitiesdescriptions import VulnerabilitiesDescriptions as VulDescrip

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


  def __returnErrorByCode(self,code):
    err = ""
    if code == "404":
      err = "Not found"

    if code[0] == "1" or code[0] == "2":
      err = "ok"

    return err


  def attackGET(self, page, dict, headers = {}):

    # Do not attack application-type files
    if not headers.has_key("content-type"):
      # Sometimes there's no content-type... so we rely on the document extension
      if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
        return
    elif headers["content-type"].find("text") == -1:
      return

    for k in self.payloads:
      url = page + k
      
      if self.verbose == 2:
        print "+ " + url

      if url not in self.attackedGET:
        self.attackedGET.append(url)
        try:
          data, code = self.HTTP.send(url).getPageCode()
          err = self.__returnErrorByCode(code)
          if err == "ok":
            if self.color == 1:
              print self.RED + _("Found backup file !") + self.STD
              print self.RED + "    -> " + url + self.STD
            else:
              print " +", _("Found backup file !")
              print "   -> " + url
            self.reportGen.logVulnerability(Vulnerability.BACKUP,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              url, "", _("Backup file found for") + " " + page)
            
        except socket.timeout:
          data = ""
          break

