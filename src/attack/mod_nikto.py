#!/usr/bin/env python
from net import BeautifulSoup
from net.httplib2 import ServerNotFoundError
from attack import Attack
from vulnerability import Vulnerability
from vulnerabilitiesdescriptions import VulnerabilitiesDescriptions as VulDescrip
import urllib2, csv

class mod_nikto(Attack):
  """
  This class implements a Nikto attack
  """

  nikto_db = []

  name = "nikto"
  CONFIG_FILE = "nikto_db"

  doGET = False
  doPOST = False

  def __init__(self, HTTP, xmlRepGenerator):
    Attack.__init__(self, HTTP, xmlRepGenerator)
    csv.register_dialect("nikto", quoting=csv.QUOTE_ALL, doublequote=False, escapechar="\\")
    try:
      fd = open(self.CONFIG_DIR + "/" + self.CONFIG_FILE)
      reader = csv.reader(fd, "nikto")
      self.nikto_db = [l for l in reader if l!=[] and l[0].isdigit()]
      fd.close()
    except IOError:
      try:
        print "Problem with local nikto database."
        print "Downloading from the web..."
        page = urllib2.urlopen("http://cirt.net/nikto/UPDATES/2.1.0/db_tests")
        reader = csv.reader(page, "nikto")
        self.nikto_db = [l for l in reader if l!=[] and l[0].isdigit()]
        page.close()

        fd = open(self.CONFIG_DIR + "/" + self.CONFIG_FILE, "w")
        writer = csv.writer(fd, "nikto")
        writer.writerows(self.nikto_db)
        fd.close()
      except IOError:
        print "Error downloading Nikto database"

  def attack(self, urls, forms):
    for l in self.nikto_db:
      match = match_or = match_and = False
      fail = fail_or = False

      if l[4] == "GET":
        l[3] = l[3].replace("@CGIDIRS","/cgi-bin/")
        l[3] = l[3].replace("@ADMIN","/admin/")
        if l[3][0] == "@":
          continue
        if l[3][0] != "/":
          l[3] = "/" + l[3]
        resp = self.HTTP.send("http://"+self.HTTP.server+l[3])
        page, code = resp.getPageCode()
        raw = " ".join([x + ": " + y for x,y in resp.getInfo().items()])
        raw += page

        # First condition (match)
        if len(l[5]) == 3 and l[5].isdigit():
          if code == l[5]:
            match = True
        else:
          if raw.find(l[5]) > -1:
            match = True

        # Second condition (or)
        if l[6] != "":
          if len(l[6]) == 3 and l[6].isdigit():
            if code == l[6]:
              match_or = True
          else:
            if raw.find(l[6]) > -1:
              match_or = True

        # Third condition (and)
        if l[7] != "":
          if len(l[7]) == 3 and l[7].isdigit():
            if code == l[7]:
              match_and = True
          else:
            if raw.find(l[7]) > -1:
              match_and = True
        else:
          match_and = True

        # Fourth condition (fail)
        if l[8] != "":
          if len(l[8]) == 3 and l[8].isdigit():
            if code == l[8]:
              fail = True
          else:
            if raw.find(l[8]) > -1:
              fail = True

        # Fifth condition (or)
        if l[9] != "":
          if len(l[9]) == 3 and l[9].isdigit():
            if code == l[9]:
              fail_or = True
          else:
            if raw.find(l[9]) > -1:
              fail_or = True

        if ((match or match_or) and match_and) and not (fail or fail_or):
          print "http://" + self.HTTP.server + l[3]
          print l[10]
          print


