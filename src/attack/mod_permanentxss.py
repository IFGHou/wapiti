#!/usr/bin/env python
import random
import re
import socket
from net import BeautifulSoup
from attack import Attack
from vulnerability import Vulnerability
from vulnerabilitiesdescriptions import VulnerabilitiesDescriptions as VulDescrip

class mod_permanentxss(Attack):
  """
  This class implements a cross site scripting attack
  """

  # magic strings we must see to be sure script is vulnerable to XSS
  # payloads must be created on those paterns
  script_ok = [
      "alert('__XSS__')",
      "alert(\"__XSS__\")",
      "String.fromCharCode(0,__XSS__,1)"
      ]

  # simple payloads that doesn't rely on their position in the DOM structure
  # payloads injected after closing a tag aatibute value (attrval) or in the
  # content of a tag (text node like beetween <p> and </p>)
  # only trick here must be on character encoding, filter bypassing, stuff like that
  # form the simplest to the most complex, Wapiti will stop on the first working
  independant_payloads = []
  
  name = "permanentxss"
  require = ["xss"]
  PRIORITY = 6

  HTTP = None

  # two dict for permanent XSS scanning
  GET_XSS = {}
  POST_XSS = {}

  CONFIG_FILE = "xssPayloads.txt"

  def __init__(self, HTTP, xmlRepGenerator):
    Attack.__init__(self, HTTP, xmlRepGenerator)
    self.independant_payloads = self.loadPayloads(self.CONFIG_DIR + "/" + self.CONFIG_FILE)

  # permanent XSS
  def attack(self, urls, forms):
    """This method searches XSS which could be permanently stored in the web application"""
    for url, headers in urls.items():
      if self.verbose >= 1:
        print "+", url
      try:
        data = self.HTTP.send(url).getPage()
      except socket.timeout:
        data = ""
      if self.doGET == 1:
        for code in self.GET_XSS.keys():
          if data.find(code) >= 0:
            # we where able to inject the ID but will we be able to inject javascript?
            for xss in self.independant_payloads:
              attack_url = self.GET_XSS[code].replace(code, xss.replace("__XSS__", code))
              try:
                self.HTTP.send(attack_url)
                dat = self.HTTP.send(url).getPage()
              except socket.timeout:
                dat = ""
              if self.validXSS(dat, code):
                if self.color == 0:
                  print _("Found permanent XSS in"), url, _("with"), attack_url
                else:
                  end = self.GET_XSS[code].index(code) - 1
                  start = self.GET_XSS[code].rfind("&", 0, end)
                  if start == -1:
                    start =  self.GET_XSS[code].rfind("?", 0, end)
                  k = self.GET_XSS[code][start+1:end]
                  print _("Found permanent XSS in"), url
                  print "  " + _("with"), attack_url.replace(k + "=", self.RED + k + self.STD + "=")

                self.reportGen.logVulnerability(Vulnerability.XSS,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY, url, "",
                                _("Found permanent XSS in") + \
                                    " " + url + " " + \
                                    _("with") + " " + self.HTTP.escape(attack_url))
                break

      headers = {"Accept": "text/plain"}
      if self.doPOST == 1:
        for code in self.POST_XSS.keys():
          if data.find(code) >= 0:
            for k, v in self.POST_XSS[code][1].items():
              if v == code:
                tmp = self.POST_XSS[code][1].copy()
                for xss in self.independant_payloads:
                  tmp[k] = xss.replace("__XSS__", code)
                  try:
                    self.HTTP.send(self.POST_XSS[code][0], self.HTTP.uqe(tmp), headers)
                    dat = self.HTTP.send(url).getPage()
                  except socket.timeout:
                    dat = ""
                  if self.validXSS(dat, code):
                    self.reportGen.logVulnerability(Vulnerability.XSS,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY, url, "",
                                _("Found permanent XSS attacked by") + " " + self.POST_XSS[code][0] + \
                                " " + _("with fields") + " " + self.HTTP.encode(tmp))
                    print _("Found permanent XSS in"), url
                    if self.color ==1:
                      print "  " + _("attacked by"), self.POST_XSS[code][2], _("with fields"), \
                          self.HTTP.uqe(tmp).replace(k + "=", self.RED + k + self.STD + "=")
                    else:
                      print "  " + _("attacked by"), self.POST_XSS[code][2], _("with fields"), self.HTTP.uqe(tmp)
                    if url != self.POST_XSS[code][0]:
                      print "  " + _("injected from ") + self.POST_XSS[code][0]
                    break

  def validXSS(self,page,code):
    soup = BeautifulSoup.BeautifulSoup(page)
    for x in soup.findAll("script"):
      if x.string != None and x.string in [t.replace("__XSS__", code) for t in self.script_ok]:
        return True
      elif x.has_key("src"):
        if x["src"] == "http://__XSS__/x.js".replace("__XSS__", code):
          return True
    return False

  def loadRequire(self, obj = []):
    self.deps = obj
    for x in self.deps:
      if x.name == "xss":
        self.GET_XSS = x.GET_XSS
        self.POST_XSS = x.POST_XSS

