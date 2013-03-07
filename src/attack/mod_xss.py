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

class mod_xss(Attack):
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
  # payloads injected after closing a tag attibute value (attrval) or in the
  # content of a tag (text node like beetween <p> and </p>)
  # only trick here must be on character encoding, filter bypassing, stuff like that
  # form the simplest to the most complex, Wapiti will stop on the first working
  independant_payloads = []
  php_self_payload = "%3Cscript%3Ephpselfxss()%3C/script%3E"
  php_self_check = "<script>phpselfxss()</script>"
  
  name = "xss"

  HTTP = None

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
          print _("XSS") + " (PHP_SELF) " + _("in"), page
          print "  " + _("Evil url") + ":", url
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
          if payloads != []:
            self.findXSS(page, {}, "", code, "", payloads, headers["link_encoding"])

    else:
      for i in range(len(params_list)):
        err = ""
        tmp = deepcopy(params_list)
        tmp[i][1] = "__XSS__"
        url = page + "?" + self.HTTP.encode(tmp) #, headers["link_encoding"])
        if url not in self.attackedGET:
          self.attackedGET.append(url)
          # genere un identifiant unique a rechercher ensuite dans la page
          code = "".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0,10)]) # don't use upercase as BS make some data lowercase
          tmp[i][1] = code
          url = page + "?" + self.HTTP.encode(tmp) #, headers["link_encoding"])
          self.GET_XSS[code] = url
          try:
            resp = self.HTTP.send(url)
            data = resp.getPage()
          except requests.exceptions.Timeout, timeout:
            data = ""
            resp = timeout
          # on effectue une recherche rapide sur l'indetifiant
          if data.find(code) >= 0:
            # identifiant est dans la page, il faut determiner ou
            payloads = self.generate_payloads(data, code)
            if payloads != []:
              self.findXSS(page, tmp, i, code, "", payloads, headers["link_encoding"])

  def attackPOST(self, form):
    """This method performs the cross site scripting attack (XSS attack) with method POST"""
    headers = {"accept": "text/plain"}
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
          print _("XSS") + " (PHP_SELF) " + _("in"), page
          print "  " + _("Evil url") + ":", url
          self.reportGen.logVulnerability(Vulnerability.XSS,
                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                            url, self.php_self_payload,
                            _("XSS") + " (PHP_SELF)")
      self.PHP_SELF.append(page)

    for i in range(len(params)):
      tmp = deepcopy(params)

      tmp[i][1] = "__XSS__"
      if (page, tmp) not in self.attackedPOST:
        self.attackedPOST.append((page, tmp))
        code = "".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0,10)]) # don't use upercase as BS make some data lowercase
        tmp[i][1] = code
        # will only memorize the last used payload (working or not) but the code will always be the good
        self.POST_XSS[code] = [page, tmp, form.referer] # [page, tmp, form[2]]
        try:
          resp = self.HTTP.send(page, post_params = self.HTTP.uqe(tmp), http_headers = headers)
          data = resp.getPage()
        except requests.exceptions.Timeout, timeout:
          data = ""
          resp = timeout
        # rapid search on the code to check injection
        if data.find(code) >= 0:
          # found, now study where the payload is injected and how to exploit it
          payloads = self.generate_payloads(data, code)
          if payloads != []:
            self.findXSS(page, tmp, i, code, form.referer, payloads, form.encoding)

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

  # check weither our JS payload is injected in the webpage
  def validXSS(self, page, code, payload):
    if page == None or page == "":
      return False
    if payload.lower() in page.lower():
      return True
    return False

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


  # Inject the JS payload codes
  # GET and POST methods here
  # * page : the url of the current webpage
  # * args : a list of the parameters, each member is a list like [key, value]
  # * index : the index of the fuzzed parameter in the args list
  # * code : a random string used to check for simple text injection
  # * referer : the url we are submitting the request from
  # * payloads : a list of payload (each one is a string)
  # * encoding : the encoding of the page
  def findXSS(self, page, args, index, code, referer, payloads, encoding=None):
    headers = {"accept": "text/plain"}
    params = deepcopy(args)
    url = page
    var = ""

    # ok let's send the requests
    for payload in payloads:

      if not params:
        url = page + "?" + self.HTTP.quote(payload)
        if self.verbose == 2:
          print "+", url
        try:
          resp = self.HTTP.send(url)
          dat = resp.getPage()
        except requests.exceptions.Timeout, timeout:
          dat = ""
          resp = timeout
        var = "QUERY_STRING"

      else:

        var = params[index][0]
        params[index][1] = self.HTTP.quote(payload)

        if referer != "": #POST
          if self.verbose == 2:
            print "+", page
            print "  ", params
          try:
            resp = self.HTTP.send(page, post_params = self.HTTP.encode(params), http_headers = headers)
            dat = resp.getPage()
          except requests.exceptions.Timeout, timeout:
            dat = ""
            resp = timeout

        else:#GET
          url = page + "?" + self.HTTP.encode(params)
          if self.verbose == 2:
            print "+", url
          try:
            resp = self.HTTP.send(url)
            dat = resp.getPage()
          except requests.exceptions.Timeout, timeout:
            dat = ""
            resp = timeout

      if self.validXSS(dat, code, payload):
        self.SUCCESSFUL_XSS[code] = payload
        if params:
          self.reportGen.logVulnerability(Vulnerability.XSS,
                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                            url, self.HTTP.encode(params),
                            _("XSS") + " (" + var + ")", resp)
        else:
          self.reportGen.logVulnerability(Vulnerability.XSS,
                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                            url, url.split("?")[1],
                            _("XSS") + " (" + var + ")", resp)

        if referer != "":
          print _("Found XSS in"), page
          if self.color == 0:
            print "  " + _("with params") + " =", self.HTTP.encode(params)
          else:
            print "  " + _("with params") + " =", self.HTTP.encode(params).replace(var + "=", self.RED + var + self.STD + "=")
          print "  " + _("coming from"), referer

        else:
          if self.color == 0:
            print _("XSS") + " (" + var + ") " + _("in"), page
            print "  " + _("Evil url") + ":", url
          else:
            print _("XSS"), ":", url.replace(var + "=", self.RED + var + self.STD + "=")
        return True

##########################################################
###### try the same things but with raw characters #######

# we still are in the "for payload" loop
      if not params:
        url = page + "?" + payload
        if self.verbose == 2:
          print "+", url
        try:
          resp = self.HTTP.send(url)
          dat = resp.getPage()
        except requests.exceptions.Timeout, timeout:
          dat = ""
          resp = timeout
        var = "QUERY_STRING"

      else:
        var = params[index][0]
        params[index][1] = payload

        if referer != "": #POST
          if self.verbose == 2:
            print "+ " + page
            print "  ", params
          try:
            resp = self.HTTP.send(page, post_params = self.HTTP.uqe(params), http_headers = headers)
            dat = resp.getPage()
          except requests.exceptions.Timeout, timeout:
            dat = ""
            resp = timeout

        else:#GET
          url = page + "?" + self.HTTP.uqe(params)
          if self.verbose == 2:
            print "+", url
          try:
            resp = self.HTTP.send(url)
            dat = resp.getPage()
          except requests.exceptions.Timeout, timeout:
            dat = ""
            resp = timeout

      if self.validXSS(dat, code, payload):
        self.SUCCESSFUL_XSS[code] = payload
        if params:
          self.reportGen.logVulnerability(Vulnerability.XSS,
                            Vulnerability.LOW_LEVEL_VULNERABILITY,
                            url, self.HTTP.encode(params),
                            _("Raw XSS") + " (" + var + ")", resp)
        else:
          self.reportGen.logVulnerability(Vulnerability.XSS,
                            Vulnerability.LOW_LEVEL_VULNERABILITY,
                            url, url.split("?")[1],
                            _("Raw XSS") + " (" + var + ")", resp)

        if referer != "":
          print _("Found raw XSS in"), page
          if self.color == 0:
            print "  " + _("with params") + " =", self.HTTP.uqe(params)
          else:
            print "  " + _("with params") + " =", self.HTTP.uqe(params).replace(var + "=", self.RED + var + self.STD + "=")
          print "  " + _("coming from"), referer

        else:
          if self.color == 0:
            print _("Raw XSS") + " (" + var + ") " + _("in"), page
            print "  " + _("Evil url") + ":", url
          else:
            print _("Raw XSS"), ":", url.replace(var + "=", self.RED + var + self.STD + "=")
        return True
##########################################################
    return False

