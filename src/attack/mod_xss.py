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
from net import HTTP

class mod_xss(Attack):
  """
  This class implements a cross site scripting attack
  """

  # magic strings we must see to be sure script is vulnerable to XSS
  # payloads must be created on those patterns
  script_ok = [
      "alert('__XSS__')",
      "alert(\"__XSS__\")",
      "String.fromCharCode(0,__XSS__,1)"
      ]

  # simple payloads that doesn't rely on their position in the DOM structure
  # payloads injected after closing a tag attibute value (attrval) or in the
  # content of a tag (text node like beetween <p> and </p>)
  # only trick here must be on character encoding, filter bypassing, stuff like that
  # form the simplest to the most complex, Wapiti will stop on the first working
  independant_payloads = []
  php_self_payload = "%3Cscript%3Ephpselfxss()%3C/script%3E"
  php_self_check = "<script>phpselfxss()</script>"
  
  name = "xss"

  # two dict exported for permanent XSS scanning
  # GET_XSS structure :
  # {uniq_code : http://url/?param1=value1&param2=uniq_code&param3..., next_uniq_code : ...}
  GET_XSS = {}
  # POST XSS structure :
  # {uniq_code : [target_url, {param1: value1, param2: uniq_code, param3:...}, referer_ul], next_uniq_code : [...]...}
  POST_XSS = {}
  PHP_SELF = []

  # key = xss code, value = payload
  SUCCESSFUL_XSS = {}

  CONFIG_FILE = "xssPayloads.txt"

  def __init__(self, HTTP, xmlRepGenerator):
    Attack.__init__(self, HTTP, xmlRepGenerator)
    self.independant_payloads = self.loadPayloads(self.CONFIG_DIR + "/" + self.CONFIG_FILE)

  def attackGET(self, http_res):
    """This method performs the cross site scripting attack (XSS attack) with method GET"""

    # copies
    page = http_res.path
    params_list = http_res.get_params
    headers = http_res.headers

    # Some PHP scripts doesn't sanitize data coming from $_SERVER['PHP_SELF']
    if page not in self.PHP_SELF:
      url = ""
      if page.endswith("/"):
        url = page + self.php_self_payload
      elif page.endswith(".php"):
        url = page + "/" + self.php_self_payload
      if url != "":
        if self.verbose == 2:
          print "+", url
        data, http_code = self.HTTP.send(url).getPageCode()
        if data.find(self.php_self_check) >= 0:
          if self.color == 0:
            print _("XSS"), "(PHP_SELF)", _("in"), page
            print "  " + _("Evil url") + ":", url
          else:
            print _("XSS"), "(PHP_SELF)", _("in"), url.replace(self.php_self_payload, self.RED + self.php_self_payload + self.STD)
          self.reportGen.logVulnerability(Vulnerability.XSS,
                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                            url, self.php_self_payload,
                            _("XSS") + " (PHP_SELF)")
      self.PHP_SELF.append(page)


    # page is the url of the script
    # params_list is a list of [key, value] lists
    if not params_list:
      # Do not attack application-type files
      if not headers.has_key("content-type"):
        # Sometimes there's no content-type... so we rely on the document extension
        if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
          return
      elif headers["content-type"].find("text") == -1:
        return

      url = page + "?__XSS__"
      if url not in self.attackedGET:
        self.attackedGET.append(url)
        err = ""
        code = "".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0,10)])
        url = page + "?" + code
        self.GET_XSS[code] = url
        try:
          resp = self.HTTP.send(url)
          data = resp.getPage()
        except requests.exceptions.Timeout:
          data = ""
          resp = None
        if data.find(code) >= 0:
          payloads = self.generate_payloads(data, code)
          for payload in payloads:
            url = page + "?" + self.HTTP.quote(payload)
            if self.verbose == 2:
              print "+", url
            try:
              resp = self.HTTP.send(url)
              dat = resp.getPage()
            except requests.exceptions.Timeout, timeout:
              dat = ""
              resp = timeout
            param_name = "QUERY_STRING"

            if dat is not None and len(dat) > 1:
              if payload.lower() in dat.lower():
                self.SUCCESSFUL_XSS[code] = payload
                self.reportGen.logVulnerability(Vulnerability.XSS,
                                  Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                  url, url.split("?")[1],
                                  _("XSS") + " (" + param_name + ")", resp)

                if self.color == 0:
                  print _("XSS"), "(QUERY_STRING)", _("in"), page
                  print "  " + _("Evil url") + ":", url
                else:
                  print _("XSS"), "(QUERY_STRING):", page + "?" + self.RED + self.HTTP.quote(payload) + self.STD
                # No more payload injection
                break


    # URL contains parameters
    else:
      for i in xrange(len(params_list)):
        err = ""
        saved_value = params_list[i][1]
        params_list[i][1] = "__XSS__"
        url = page + "?" + self.HTTP.encode(params_list)
        if url not in self.attackedGET:
          self.attackedGET.append(url)
          # Create a random unique ID that will be used to test injection
          code = "".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0,10)]) # don't use upercase as BS make some data lowercase
          params_list[i][1] = code
          url = page + "?" + self.HTTP.encode(params_list) #, headers["link_encoding"])
          self.GET_XSS[code] = url
          try:
            resp = self.HTTP.send(url)
            data = resp.getPage()
          except requests.exceptions.Timeout, timeout:
            data = ""
            resp = timeout
          # is the random code on the webpage ?
          if data.find(code) >= 0:
            # YES! But where exactly ?
            payloads = self.generate_payloads(data, code)
            for payload in payloads:

              param_name = self.HTTP.quote(params_list[i][0])
              params_list[i][1] = payload

              url = page + "?" + self.HTTP.encode(params_list)
              if self.verbose == 2:
                print "+", url
              try:
                resp = self.HTTP.send(url)
                dat = resp.getPage()
              except requests.exceptions.Timeout, timeout:
                dat = ""
                resp = timeout

              if dat is not None and len(dat) > 1:
                if payload.lower() in dat.lower():
                  self.SUCCESSFUL_XSS[code] = payload
                  self.reportGen.logVulnerability(Vulnerability.XSS,
                                    Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                    url, self.HTTP.encode(params_list),
                                    _("XSS") + " (" + param_name + ")", resp)

                  if self.color == 0:
                    print _("XSS") + " (" + param_name + ") " + _("in"), page
                    print "  " + _("Evil url") + ":", url
                  else:
                    print _("XSS"), ":", url.replace(param_name + "=", self.RED + param_name + self.STD + "=")
                  # stop trying payloads and jum to the next parameter
                  break
        # Restore the value of this argument before testing the next one
        params_list[i][1] = saved_value

  def attackPOST(self, form):
    """This method performs the cross site scripting attack (XSS attack) with method POST"""
    page = form.url # form[0]
    params = form.post_params # form[1]

    if page not in self.PHP_SELF:
      url = ""
      if page.endswith("/"):
        url = page + self.php_self_payload
      elif page.endswith(".php"):
        url = page + "/" + self.php_self_payload
      if url != "":
        if self.verbose == 2:
          print "+", url
        data, http_code = self.HTTP.send(url).getPageCode()
        if data.find(self.php_self_check) >= 0:
          if self.color == 0:
            print _("XSS"), "(PHP_SELF)", _("in"), page
            print "  " + _("Evil url") + ":", url
          else:
            print _("XSS"), "(PHP_SELF)", _("in"), url.replace(self.php_self_payload, self.RED + self.php_self_payload + self.STD)
          self.reportGen.logVulnerability(Vulnerability.XSS,
                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                            url, self.php_self_payload,
                            _("XSS") + " (PHP_SELF)")
      self.PHP_SELF.append(page)

    # copies
    get_params  = form.get_params
    post_params = form.post_params
    file_params = form.file_params

    for param_list in [get_params, post_params, file_params]:
      for i in xrange(len(param_list)):
        saved_value = param_list[i][1]
        param_list[i][1] = "__XSS__"
        # We keep an attack pattern to make sure a given form won't be attacked on the same field several times
        attack_pattern = HTTP.HTTPResource(form.path, method=form.method, get_params=get_params, post_params=post_params, file_params=file_params)
        if not attack_pattern in self.attackedPOST:
          self.attackedPOST.append(attack_pattern)
          code = "".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0,10)]) # don't use upercase as BS make some data lowercase
          param_list[i][1] = code
          # will only memorize the last used payload (working or not) but the code will always be the good
          test_payload = HTTP.HTTPResource(form.path,
              method=form.method,
              get_params=get_params,
              post_params=post_params,
              file_params=file_params,
              referer=form.referer)

          self.POST_XSS[code] = test_payload
          try:
            resp = self.HTTP.send(test_payload)
            data = resp.getPage()
          except requests.exceptions.Timeout, timeout:
            data = ""
            resp = timeout
          # rapid search on the code to check injection
          if data.find(code) >= 0:
            # found, now study where the payload is injected and how to exploit it
            payloads = self.generate_payloads(data, code)
            for payload in payloads:
              param_name = param_list[i][0]
              param_list[i][1] = payload

              evil_req = HTTP.HTTPResource(form.path, method=form.method, get_params=get_params, post_params=post_params, file_params=file_params)

              if self.verbose == 2:
                print "+", evil_req
              try:
                resp = self.HTTP.send(evil_req)
                dat = resp.getPage()
              except requests.exceptions.Timeout, timeout:
                dat = ""
                resp = timeout

              if dat is not None and len(dat) > 1:
                if payload.lower() in dat.lower():
                  self.SUCCESSFUL_XSS[code] = payload
                  self.reportGen.logVulnerability(Vulnerability.XSS,
                                    Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                    evil_req.url, self.HTTP.encode(post_params),
                                    _("XSS") + " (" + param_name + ")", resp)

                  #TODO: vuln param name may appear twice (or more)
                  if self.color == 0:
                    print _("Found XSS in"), evil_req.url
                    print "  " + _("with params") + " =", self.HTTP.encode(post_params)
                  else:
                    if param_list is get_params:
                      print _("Found XSS in"), evil_req.url.replace(param_name + "=", self.RED + param_name + self.STD + "=")
                      print "  " + _("with params") + " =", self.HTTP.encode(post_params)
                    else:
                      print _("Found XSS in"), evil_req.url
                      print "  " + _("with params") + " =", self.HTTP.encode(post_params).replace(param_name + "=", self.RED + param_name + self.STD + "=")
                  print "  " + _("coming from"), form.referer
                  # Stop injecting payloads and move to the next parameter
                  break

        # restore the saved parameter in the list
        param_list[i][1] = saved_value


  # type/name/tag ex: attrval/img/src
  # TODO: entries is a mutable argument, check this
  def study(self, obj, parent=None, keyword="", entries=[]):
    #if parent==None:
    #  print "Keyword is:",keyword
    if str(obj).find(keyword) >= 0:
      if isinstance(obj, BeautifulSoup.Tag):
        if str(obj.attrs).find(keyword) >= 0:
          for k, v in obj.attrs:
            if v.find(keyword) >= 0:
              #print "Found in attribute value ",k,"of tag",obj.name
              entries.append({"type":"attrval", "name":k, "tag":obj.name})
            if k.find(keyword) >= 0:
              #print "Found in attribute name ",k,"of tag",obj.name
              entries.append({"type":"attrname", "name":k, "tag":obj.name})
        elif obj.name.find(keyword) >= 0:
          #print "Found in tag name"
          entries.append({"type":"tag", "value":obj.name})
        else:
          for x in obj.contents:
            self.study(x, obj, keyword, entries)
      elif isinstance(obj, BeautifulSoup.NavigableString):
        if str(obj).find(keyword) >= 0:
          #print "Found in text, tag", parent.name
          entries.append({"type":"text", "parent":parent.name})


  # generate a list of payloads based on where in the webpage the js-code will be injected
  def generate_payloads(self, data, code):
    headers = {"accept": "text/plain"}
    soup = BeautifulSoup.BeautifulSoup(data) # il faut garder la page non-retouchee en reserve...
    e = []
    self.study(soup, keyword = code, entries = e)

    payloads = []

    for elem in e:
      payload = ""
      # Try each case where our string can be found
      # Leave at the first possible exploitation found

      # Our string is in the value of a tag attribute
      # ex: <a href="our_string"></a>
      if elem['type'] == "attrval":
        #print "tag->"+elem['tag']
        #print elem['name']
        i0 = data.find(code)
        #i1=data[:i0].rfind("=")
        try:
          # find the position of name of the attribute we are in
          i1 = data[:i0].rfind(elem['name'])
        # stupid unicode errors, must check later
        except UnicodeDecodeError:
          continue

        start = data[i1:i0].replace(" ", "")[len(elem['name']):]
        # between the tag name and our injected attribute there is an equal sign
        # and (probably) a quote or a double-quote we need to close before putting our payload
        if start.startswith("='"): payload="'"
        if start.startswith('="'): payload='"'
        if elem['tag'].lower() == "img":
          payload += "/>"
        else:
          payload += "></" + elem['tag'] + ">"

        # ok let's send the requests
        for xss in self.independant_payloads:
          payloads.append(payload + xss.replace("__XSS__", code))

      # we control an attribute name
      # ex: <a our_string="/index.html">
      elif elem['type'] == "attrname": # name,tag
        if code == elem['name']:
          for xss in self.independant_payloads:
            payloads.append('>' + xss.replace("__XSS__",code))

      # we control the tag name
      # ex: <our_string name="column" />
      elif elem['type'] == "tag":
        if elem['value'].startswith(code):
          # use independant payloads, just remove the first character (<)
          for xss in self.independant_payloads:
            payloads.append(xss.replace("__XSS__", code)[1:])
        else:
          for xss in self.independant_payloads:
            payloads.append("/>" + xss.replace("__XSS__", code))

      # we control the text of the tag
      # ex: <textarea>our_string</textarea>
      elif elem['type'] == "text":
        payload = ""
        if elem['parent'] == "title": # Oops we are in the head
          payload = "</title>"

        for xss in self.independant_payloads:
          payloads.append(payload + xss.replace("__XSS__", code))
        return payloads

      data = data.replace(code, "none", 1)#reduire la zone de recherche
    return payloads

