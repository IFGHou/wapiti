#!/usr/bin/env python
from net import BeautifulSoup
from net.httplib2 import ServerNotFoundError
from attack import Attack
from vulnerability import Vulnerability
from vulnerabilitiesdescriptions import VulnerabilitiesDescriptions as VulDescrip
import urllib2, csv, re
import socket

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
    try:
      fd = open(self.CONFIG_DIR + "/" + self.CONFIG_FILE)
      reader = csv.reader(fd)
      self.nikto_db = [l for l in reader if l!=[] and l[0].isdigit()]
      fd.close()
    except IOError:
      try:
        print _("Problem with local nikto database.")
        print _("Downloading from the web...")
        page = urllib2.urlopen("http://cirt.net/nikto/UPDATES/2.1.0/db_tests")
        csv.register_dialect("nikto", quoting=csv.QUOTE_ALL, doublequote=False, escapechar="\\")
        reader = csv.reader(page, "nikto")
        self.nikto_db = [l for l in reader if l!=[] and l[0].isdigit()]
        page.close()

        fd = open(self.CONFIG_DIR + "/" + self.CONFIG_FILE, "w")
        writer = csv.writer(fd)
        writer.writerows(self.nikto_db)
        fd.close()
      except socket.timeout:
        print _("Error downloading Nikto database")

  def attack(self, urls, forms):
    for l in self.nikto_db:
      match = match_or = match_and = False
      fail = fail_or = False

      l[3] = l[3].replace("@CGIDIRS", "/cgi-bin/")
      l[3] = l[3].replace("@ADMIN", "/admin/")
      l[3] = l[3].replace("@NUKE", "/modules/")
      l[3] = l[3].replace("@PHPMYADMIN", "/phpMyAdmin/")
      l[3] = l[3].replace("@POSTNUKE", "/postnuke/")
      if l[3][0] == "@":
        continue
      if l[3][0] != "/":
        l[3] = "/" + l[3]

      if l[4] == "GET":
        resp = self.HTTP.send("http://" + self.HTTP.server + l[3])
      elif l[4] == "POST":
        resp = self.HTTP.send("http://" + self.HTTP.server + l[3], l[11])
      else:
        resp = self.HTTP.send("http://" + self.HTTP.server + l[3], l[11], method = l[4])

      page, code = resp.getPageCode()
      encoding = BeautifulSoup.BeautifulSoup(page).originalEncoding
      page = unicode(page, encoding, "ignore")
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
        refs = []
        if l[1] != "0":
          refs.append("http://osvdb.org/show/osvdb/" + l[1])

        # CERT
        m = re.search("(CA\-[0-9]{4}-[0-9]{2})", l[10])
        if m != None:
          refs.append("http://www.cert.org/advisories/" + m.group(0) + ".html")
        
        # SecurityFocus
        m = re.search("BID\-([0-9]{4})", l[10])
        if m != None:
          refs.append("http://www.securityfocus.com/bid/" + m.group(1))

        # Mitre.org
        m = re.search("((CVE|CAN)\-[0-9]{4}-[0-9]{4})", l[10])
        if m != None:
          refs.append("http://cve.mitre.org/cgi-bin/cvename.cgi?name=" + m.group(0))

        # CERT Incidents
        m = re.search("(IN\-[0-9]{4}\-[0-9]{2})", l[10])
        if m != None:
          refs.append("http://www.cert.org/incident_notes/" + m.group(0) + ".html")

        # Microsoft Technet
        m = re.search("(MS[0-9]{2}\-[0-9]{3})", l[10])
        if m != None:
          refs.append("http://www.microsoft.com/technet/security/bulletin/" + m.group(0) + ".asp")

        info = l[10]
        if refs != []:
          print _("References:") +"\n  " + "\n  ".join(refs)
          info += "\n" + _("References:") + "\n"
          info += "\n".join(['<a href="' + x + '">' + x + '</a>' for x in refs])
        print


        if l[4] == "GET":
          self.reportGen.logVulnerability(Vulnerability.NIKTO, Vulnerability.HIGH_LEVEL_VULNERABILITY,
              "http://" + self.HTTP.server + l[3], "", info)
        elif l[4] == "POST":
          self.reportGen.logVulnerability(Vulnerability.NIKTO, Vulnerability.HIGH_LEVEL_VULNERABILITY,
              "http://" + self.HTTP.server + l[3], l[11], info)
        else:
          self.reportGen.logVulnerability(Vulnerability.NIKTO, Vulnerability.HIGH_LEVEL_VULNERABILITY,
              "http://" + self.HTTP.server + l[3], l[4] + " " + l[11], info)

