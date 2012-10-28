#!/usr/bin/env python
import lswww
import urllib
import urlparse
import socket
import os
import cgi
import requests
import datetime

class HTTPResponse:
  data = ""
  code = "200"
  headers = {}

  def __init__(self, data, code, headers, peer, timestamp, encoding = ""):
    self.data = data
    self.code = code
    self.headers = headers
    self.peer = peer
    self.timestamp = timestamp
    self.encoding = encoding

  def getPage(self):
    "Return the content of the page."
    return self.data

  def getRawPage(self):
    "Return the content of the page."
    return self.data.encode(self.encoding)

  def getCode(self):
    "Return the HTTP Response code ."
    return self.code

  def getInfo(self):
    "Return the HTTP headers of the Response."
    return self.headers

  def getPageCode(self):
    "Return a tuple of the content and the HTTP Response code."
    return (self.data, self.code)

  def getPeer(self):
    """Return the network address of the server that delivered this Response.
    This will always be a socket_object.getpeername() return value, which is
    normally a (ip_address, port) tuple."""
    return self.peer

  def getTimestamp(self):
    """Return a datetime.datetime object describing when this response was
    received."""
    return self.timestamp

class HTTP:
  root = ""
  myls = ""
  server = ""
  cookie = ""
  proxy = ""
  auth_basic = []
  timeout = 6
  h = None
  cookiejar = None

  configured = 0

  def __init__(self, root):
    error_str = ""
    self.myls = lswww.lswww(root)
    self.root = self.myls.root
    self.server = urlparse.urlparse(self.root)[1]
    self.myls.verbosity(1)
    socket.setdefaulttimeout(self.timeout)

  def init(self):
    # HttpLib2 vars
    proxy = None

    #TODO: bring back proxy sypport, auth and cookie serialization
    self.h = requests.session(proxies = {})
    
  def browse(self, crawlerFile):
    "Explore the entire website under the pre-defined root-url."
    self.myls.go(crawlerFile)
    urls  = self.myls.getLinks()
    forms = self.myls.getForms()
    return urls, forms

  def getUploads(self):
    "Return the url of the pages used for file uploads."
    return self.myls.getUploads()

  def send(self, target, post_data = None, http_headers = {}, method=""):
    "Send a HTTP Request. GET or POST (if post_data is set)."

    if self.configured == 0:
      self.init()
      self.configured = 1

    data = ""
    code = "0"
    info = {}
    _headers = {}
    _headers.update(http_headers)
    if post_data == None:
      resp = self.h.get(target, headers = _headers)
    else:
      _headers.update({'Content-type': 'application/x-www-form-urlencoded'})
      resp = self.h.post(target, headers = _headers, data = post_data)
    data = resp.text
    info = resp.headers
    code = resp.status_code
    return HTTPResponse(data, code, info, "", datetime.datetime.now(), encoding = resp.encoding)

  def quote(self, url):
    "Encode a string with hex representation (%XX) for special characters."
    return urllib.quote(url)

  def encode(self, url, encoding = None):
    "Encode a sequence of two-element tuples or dictionary into a URL query string."
    if encoding != None and encoding != "":
      tmp = {}
      for k, v in url.items():
        tmp[k.encode(encoding, "ignore")] = v.encode(encoding, "ignore")
      return urllib.urlencode(tmp)
    return urllib.urlencode(url)

  def uqe(self, url, encoding = None):
    "urlencode a string then interpret the hex characters (%41 will give 'A')."
    return urllib.unquote(self.encode(url, encoding))

  def escape(self,url):
    "Change special characters in their html entities representation."
    return cgi.escape(url, quote = True).replace("'", "%27")

  def setTimeOut(self, timeout = 6):
    "Set the time to wait for a response from the server."
    self.timeout = timeout
    self.myls.setTimeOut(timeout)

  def getTimeOut(self):
    "Return the timeout used for HTTP requests."
    return self.timeout

  def setProxy(self, proxy = ""):
    "Set a proxy to use for HTTP requests."
    self.proxy = proxy
    self.myls.setProxy(proxy)

  def addStartURL(self, url):
    "Specify an URL to start the scan with. Can be called several times."
    self.myls.addStartURL(url)

  def addExcludedURL(self, url):
    "Specify an URL to exclude from the scan. Can be called several times."
    self.myls.addExcludedURL(url)

  def setCookieFile(self, cookie):
    "Load session data from a cookie file"
    self.cookie = cookie
    if os.path.isfile(self.cookie):
      self.cookiejar.loadfile(self.cookie)
      self.myls.setCookieFile(cookie)

  def setAuthCredentials(self, auth_basic):
    "Set credentials to use if the website require an authentification."
    self.auth_basic = auth_basic
    self.myls.setAuthCredentials(auth_basic)

  def addBadParam(self, bad_param):
    """Exclude a parameter from an url (urls with this parameter will be
    modified. This function can be call several times"""
    self.myls.addBadParam(bad_param)

  def setNice(self, nice = 0):
    """Define how many tuples of parameters / values must be sent for a
    given URL. Use it to prevent infinite loops."""
    self.myls.setNice(nice)

  def setScope(self, scope):
    """Set the scope of the crawler for the analysis of the web pages"""
    self.myls.setScope(scope)

  def verbosity(self, vb):
    "Define the level of verbosity of the output."
    self.myls.verbosity(vb)

