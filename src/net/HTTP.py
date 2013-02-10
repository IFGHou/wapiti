#!/usr/bin/env python
import lswww
import urllib
import urlparse
import socket
import os
import cgi
import requests
import datetime
import jsoncookie

class HTTPResource:
  method = "GET"
  encoding = "UTF-8"
  resource_uri = ""
  post_data = [] # table of tuples
  encoded_post_data = ""
  _hash = None
  
  def __init__(self, url, method = "GET", post_data = [], encoding = "UTF-8", referer = ""):
    self.method = method
    self.resource_uri = url
    self.post_data = post_data
    if self.post_data:
      self.method = "POST"
    self.encoding = encoding
    self.referer = referer

    self.encoded_post_data = self.encoded_data()

  def __hash__(self):
    if self._hash:
      return self._hash

    if not self.post_data:
      self._hash = hash(self.resource_uri)
    else:
      self._hash = hash( frozenset( [self.resource_uri] + [d[0] for d in self.post_data] ) )
    return self._hash

  def __eq__(self, other):
    if not isinstance(other, HTTPResource):
      return False
    if self.method != other.method:
      return False
    if self.resource_uri != other.resource_uri:
      return False
    if self.post_data:
      if other.post_data:
        return hash(self) == hash(other)
      else:
        return False
    else:
      if other.post_data:
        return False
      else:
        return True

  def encoded_data(self):
    """Return a raw string of key/value parameters for POST requests"""
    if not self.post_data:
      return ""

    if self.encoded_post_data:
      return self.encoded_post_data

    quoted_key_values = []
    for k, v in self.post_data:
      k = urllib.quote(k.encode(self.encoding, "ignore"))
      v = urllib.quote(v.encode(self.encoding, "ignore"))
      quoted_key_values.append("%s=%s" % (k, v))
    self.encoded_post_data = "&".join(quoted_key_values)
    return self.encoded_post_data

  def url(self):
    return self.resource_uri

 
class HTTPResponse:
  resp = None

  def __init__(self, requests_resp, peer, timestamp):
    self.resp = requests_resp
    self.peer = peer
    self.timestamp = timestamp

  def getPage(self):
    "Return the content of the page in unicode."
    if self.resp.encoding:
      return self.resp.text
    else:
      return self.resp.content

  def getRawPage(self):
    "Return the content of the page in raw bytes."
    return self.resp.content

  def getCode(self):
    "Return the HTTP Response code ."
    return str(self.resp.status_code)

  def getHeaders(self):
    "Return the HTTP headers of the Response."
    return self.resp.headers

  def getPageCode(self):
    "Return a tuple of the content and the HTTP Response code."
    return (self.getPage(), self.resp.status_code)

  def getEncoding(self):
    "Return the detected encoding for the page."
    return self.resp.encoding

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
  proxies = {}
  auth_basic = []
  timeout = 6.0
  h = None
  cookiejar = None
  server = ""

  configured = 0

  def __init__(self, server):
    #TODO: bring back auth (htaccess)
    self.h = requests.session(proxies = self.proxies, cookies = self.cookiejar)
    self.server = server
    
  def send(self, target, method = "", post_data = [], http_headers = {}):
    "Send a HTTP Request. GET or POST (if post_data is set)."
    resp = None
    _headers = {}
    _headers.update(http_headers)

    if not method:
      if post_data:
        method = "POST"
      else:
        method = "GET"

    if isinstance(target, HTTPResource):
      if target.method == "GET":
        resp = self.h.get(target.url(), headers = _headers, timeout = self.timeout, allow_redirects = False)
      else:
        _headers.update({'content-type': 'application/x-www-form-urlencoded'})
        if target.referer:
          _headers.update({'referer': target.referer})
        # TODO: For POST use the TooManyRedirects exception instead ?
        resp = self.h.post(target.url(), headers = _headers, data = target.encoded_data(), timeout = self.timeout, allow_redirects = False)

    else:
      if method == "GET":
        resp = self.h.get(target, headers = _headers, timeout = self.timeout, allow_redirects = False)
      elif method == "POST":
        _headers.update({'content-type': 'application/x-www-form-urlencoded'})
        resp = self.h.post(target, headers = _headers, data = post_data, timeout = self.timeout, allow_redirects = False)
      else:
        resp = self.h.request(method, target, timeout = self.timeout, allow_redirects = False)

    if resp == None:
      return None
    return HTTPResponse(resp, "", datetime.datetime.now())

  def quote(self, url):
    "Encode a string with hex representation (%XX) for special characters."
    return urllib.quote(url)

  def encode(self, params_list, encoding = None):
    "Encode a sequence of two-element lists or dictionary into a URL query string."
    if not encoding:
      encoding = "ISO-8859-1"
    encoded_params = []
    for param in params_list:
      k, v = param
      k = self.quote(k.encode(encoding, "ignore"))
      v = self.quote(v.encode(encoding, "ignore"))
      encoded_params.append("%s=%s" % (k, v))
    return "&".join(encoded_params)

  def uqe(self, params_list, encoding = None):
    "urlencode a string then interpret the hex characters (%41 will give 'A')."
    return urllib.unquote(self.encode(params_list, encoding))

  def escape(self,url):
    "Change special characters in their html entities representation."
    return cgi.escape(url, quote = True).replace("'", "%27")

  def setTimeOut(self, timeout = 6.0):
    "Set the time to wait for a response from the server."
    self.timeout = timeout
    socket.setdefaulttimeout(self.timeout)

  def getTimeOut(self):
    "Return the timeout used for HTTP requests."
    return self.timeout

  def setProxy(self, proxy = ""):
    "Set a proxy to use for HTTP requests."
    url_parts = urlparse.urlparse(proxy)
    protocol = url_parts.scheme
    host = url_parts.netloc
    if protocol in ["http", "https"]:
      if host:
        self.proxies[protocol] = "%s://%s/" % (protocol, host)

  def setCookieFile(self, cookie):
    "Load session data from a cookie file"
    if os.path.isfile(cookie):
      jc = jsoncookie.jsoncookie()
      jc.open(cookie)
      self.cookiejar = jc.cookiejar(self.server)
      jc.close()

  def setAuthCredentials(self, auth_basic):
    "Set credentials to use if the website require an authentification."
    self.auth_basic = auth_basic
