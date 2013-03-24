#!/usr/bin/env python
import random
import re
import socket
import BeautifulSoup
import requests
from attack import Attack
from vulnerability import Vulnerability
from vulnerabilitiesdescriptions import VulnerabilitiesDescriptions as VulDescrip
from net import HTTP

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
  def attack(self, get_resources, forms):
    """This method searches XSS which could be permanently stored in the web application"""
    for http_resource in get_resources:
      if http_resource.method != "GET":
        continue
      url = http_resource.url
      referer = http_resource.referer
      headers = {}
      if referer:
        headers["referer"] = referer
      if self.verbose >= 1:
        print "+", url
      try:
        resp = self.HTTP.send(url, headers=headers)
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
        for code in self.GET_XSS:
          if code in data:
            # code found in the webpage !
            if code in self.SUCCESSFUL_XSS:
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
            else:
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

      if self.doPOST == 1:
        for code in self.POST_XSS:
          if code in data:
            # code found in the webpage
            if code in self.SUCCESSFUL_XSS:
              # this code has been used in a successful attack
              if self.validXSS(data, code, self.SUCCESSFUL_XSS[code]):
                
                code_req = self.POST_XSS[code]
                get_params  = code_req.get_params
                post_params = code_req.post_params
                file_params = code_req.file_params
                referer = code_req.referer

                for params_list in [get_params, post_params, file_params]:
                  for i in xrange(len(params_list)):
                    param_name, v = params_list[i]
                    param_name = self.HTTP.quote(param_name)
                    if v == code:
                      params_list[i][1] = self.SUCCESSFUL_XSS[code]
                      # we found the xss payload again -> stored xss vuln
                      evil_req = HTTP.HTTPResource(code_req.path,
                          method="POST",
                          get_params=get_params,
                          post_params=post_params,
                          file_params=file_params,
                          referer=referer)

                      self.reportGen.logVulnerability(Vulnerability.XSS,
                                  Vulnerability.HIGH_LEVEL_VULNERABILITY, url, "",
                                  _("Found permanent XSS attacked by") + " " + evil_req.url + \
                                  " " + _("with fields") + " " + self.HTTP.encode(post_params), resp)
                      print _("Found permanent XSS in"), url
                      if self.color ==1:
                        print "  " + _("attacked by"), evil_req.url, _("with fields"), \
                            self.HTTP.encode(post_params).replace(param_name + "=", self.RED + param_name + self.STD + "=")
                      else:
                        print "  " + _("attacked by"), evil_req.url, _("with fields"), self.HTTP.encode(post_params)
                      if url != evil_req.url:
                        print "  " + _("injected from ") + referer
                      # search for the next code in the webpage
                  continue

            # we found the code but no attack was made
            # let's try to break in
            else:
              code_req = self.POST_XSS[code]
              get_params  = code_req.get_params
              post_params = code_req.post_params
              file_params = code_req.file_params
              referer = code_req.referer

              for params_list in [get_params, post_params, file_params]:
                for i in xrange(len(params_list)):
                  param_name, v = params_list[i]
                  param_name = self.HTTP.quote(param_name)
                  if v == code:
                    for xss in self.independant_payloads:
                      payload = xss.replace("__XSS__", code)
                      params_list[i][1] = payload
                      try:
                        evil_req = HTTP.HTTPResource(code_req.path,
                            method=code_req.method,
                            get_params=get_params,
                            post_params=post_params,
                            file_params=file_params,
                            referer=referer)
                        self.HTTP.send(evil_req)
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
                                    _("Found permanent XSS attacked by") + " " + evil_req.url + \
                                    " " + _("with fields") + " " + self.HTTP.encode(post_params), resp)

                        print _("Found permanent XSS in"), url
                        if self.color ==1:
                          print "  " + _("attacked by"), evil_req.url, _("with fields"), \
                              self.HTTP.encode(post_params).replace(param_name + "=", self.RED + param_name + self.STD + "=")
                        else:
                          print "  " + _("attacked by"), evil_req.url, _("with fields"), self.HTTP.encode(post_params)
                        if url != evil_req.url:
                          print "  " + _("injected from ") + referer
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

