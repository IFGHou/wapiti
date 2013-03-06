#!/usr/bin/env python
import random
import re
import socket
import BeautifulSoup
import requests
from attack import Attack
from vulnerability import Vulnerability
from vulnerabilitiesdescriptions import VulnerabilitiesDescriptions as VulDescrip
from copy import deepcopy

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

  # key = xss code, valud = payload
  SUCCESSFUL_XSS = {}

  CONFIG_FILE = "xssPayloads.txt"

  def __init__(self, HTTP, xmlRepGenerator):
    Attack.__init__(self, HTTP, xmlRepGenerator)
    self.independant_payloads = self.loadPayloads(self.CONFIG_DIR + "/" + self.CONFIG_FILE)

  # permanent XSS
  def attack(self, urls, forms):
    """This method searches XSS which could be permanently stored in the web application"""
    for http_resource, headers in urls.items():
      url = http_resource.url
      if self.verbose >= 1:
        print "+", url
      try:
        resp = self.HTTP.send(url)
        data = resp.getPage()
      except requests.exceptions.Timeout, timeout:
        data = ""
        resp = timeout
      except socket.error, se:
        data = ""
        resp = None
        print 'error: %s while attacking %s' % (repr(str(se[1])), url)
      except Exception, e:
        print 'error: %s while attacking %s' % (repr(str(e[0])), url)
        continue

      # Search for permanent XSS vulns which were injected via GET
      if self.doGET == 1:
        for code in self.GET_XSS.keys():
          if code in data:
            # code found in the webpage !
            if code in self.SUCCESSFUL_XSS.keys():
              # is this an already known vuln (reflected XSS)
              if self.validXSS(data, code, self.SUCCESSFUL_XSS[code]):
                # if we can find the payload again, this is a stored XSS
                attack_url = self.GET_XSS[code].replace(code, self.SUCCESSFUL_XSS[code])
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
                                    _("with") + " " + self.HTTP.escape(attack_url), resp)
                # we reported the vuln, now search another code
                continue

            # we where able to inject the ID but will we be able to inject javascript?
            for xss in self.independant_payloads:
              payload = xss.replace("__XSS__", code)
              attack_url = self.GET_XSS[code].replace(code, payload)
              try:
                self.HTTP.send(attack_url)
                resp = self.HTTP.send(url)
                dat = resp.getPage()
              except requests.exceptions.Timeout, timeout:
                dat = ""
                resp = timeout
              except Exception, e:
                print 'error: %s while attacking %s' % (repr(str(e[0])), url)
                continue

              if self.validXSS(dat, code, payload):
                # injection successful :)
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
                                    _("with") + " " + self.HTTP.escape(attack_url), resp)
                # look for another code in the webpage
                break

      headers = {"accept": "text/plain"}
      if self.doPOST == 1:
        for code in self.POST_XSS.keys():
          if code in data:
            # code found in the webpage
            if code in self.SUCCESSFUL_XSS.keys():
              # this code has been used in a successful attack
              if self.validXSS(data, code, self.SUCCESSFUL_XSS[code]):
                tmp = deepcopy(self.POST_XSS[code][1])
                for i in range(len(tmp)):
                  k, v = tmp[i]
                  if v == code:
                    tmp[i][1] = self.SUCCESSFUL_XSS[code]
                    break
                # we found the xss payload again -> stored xss vuln
                self.reportGen.logVulnerability(Vulnerability.XSS,
                            Vulnerability.HIGH_LEVEL_VULNERABILITY, url, "",
                            _("Found permanent XSS attacked by") + " " + self.POST_XSS[code][0] + \
                            " " + _("with fields") + " " + self.HTTP.encode(tmp), resp)
                print _("Found permanent XSS in"), url
                if self.color ==1:
                  print "  " + _("attacked by"), self.POST_XSS[code][2], _("with fields"), \
                      self.HTTP.uqe(tmp).replace(k + "=", self.RED + k + self.STD + "=")
                else:
                  print "  " + _("attacked by"), self.POST_XSS[code][2], _("with fields"), self.HTTP.uqe(tmp)
                if url != self.POST_XSS[code][0]:
                  print "  " + _("injected from ") + self.POST_XSS[code][0]
                # search for the next code in the webpage
                continue

            # we found the code but no attack was made
            # let's try to break in
            params_list = self.POST_XSS[code][1]
            for i in range(len(params_list)):
              k, v = params_list[i]
              if v == code:
                tmp = deepcopy(params_list)
                for xss in self.independant_payloads:
                  payload = xss.replace("__XSS__", code)
                  tmp[i][1] = payload
                  try:
                    self.HTTP.send(self.POST_XSS[code][0], post_params = self.HTTP.uqe(tmp), http_headers = headers)
                    resp = self.HTTP.send(url)
                    dat = resp.getPage()
                  except requests.exceptions.Timeout, timeout:
                    dat = ""
                    resp = timeout
                  except Exception, e:
                    print 'error: %s while attacking %s' % (repr(str(e[0])), url)
                    continue
                  if self.validXSS(dat, code, payload):
                    self.reportGen.logVulnerability(Vulnerability.XSS,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY, url, "",
                                _("Found permanent XSS attacked by") + " " + self.POST_XSS[code][0] + \
                                " " + _("with fields") + " " + self.HTTP.encode(tmp), resp)
                    print _("Found permanent XSS in"), url
                    if self.color ==1:
                      print "  " + _("attacked by"), self.POST_XSS[code][2], _("with fields"), \
                          self.HTTP.uqe(tmp).replace(k + "=", self.RED + k + self.STD + "=")
                    else:
                      print "  " + _("attacked by"), self.POST_XSS[code][2], _("with fields"), self.HTTP.uqe(tmp)
                    if url != self.POST_XSS[code][0]:
                      print "  " + _("injected from ") + self.POST_XSS[code][0]
                    break

  # check weither our JS payload is injected in the webpage
  def validXSS(self, page, code, payload):
    if page == None or page == "":
      return False
    if payload.lower() in page.lower():
      return True
    return False

  def loadRequire(self, obj = []):
    self.deps = obj
    for x in self.deps:
      if x.name == "xss":
        self.GET_XSS = x.GET_XSS
        self.POST_XSS = x.POST_XSS
        self.SUCCESSFUL_XSS = x.SUCCESSFUL_XSS

