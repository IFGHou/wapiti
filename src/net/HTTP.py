#!/usr/bin/env python
import urllib
import urlparse
import socket
import os
import cgi
import requests
import datetime
import jsoncookie
from copy import deepcopy

class HTTPResource(object):
  _method = "GET"
  _encoding = "ISO-8859-1"
  _resource_path = ""
  _status = 0
  _headers = {}
  _referer = ""

  # eg: get = [['id', '25'], ['color', 'green']]
  _get_params = []

  # same structure as _get_params
  _post_params = []

  # eg: files = [['file_field', ('file_name', 'file_content')]]
  _file_params = []
  
  def __init__(self, path, method="", get_params=None, post_params=None, encoding="UTF-8", referer="", file_params=None):
    """Create a new HTTPResource object.

    Takes the following arguments:
      path : The path of the HTTP resource on the server. It can contain a query string.
      get_params : A list of key/value parameters (each one is a list of two string).
                   Each string should already be urlencoded in the good encoding format.
      post_params : Same structure as above but specify the parameters sent in the HTTP body.
      file_params : Same as above expect the values are a tuple (filename, file_content).
      encoding : A string specifying the encoding used to send data to this URL.
                 Don't mistake it with the encoding of the webpage pointed out by the HTTPResource.
      referer : The URL from which the current HTTPResource was found.
    """
    self._resource_path = path

    if post_params is None:
      self._post_params = []
    else:
      self._post_params = post_params

    if file_params is None:
      self._file_params = []
    else:
      self._file_params = file_params

    if get_params is None:
      self._get_params = []
      if "?" in self._resource_path:
        query_string = urlparse.urlparse(self._resource_path).query
        for kv in query_string.split("&"):
          if kv.find("=") > 0:
            self._get_params.append(kv.split("=", 1))
        self._resource_path = self._resource_path.split("?")[0]
    else:
      self._get_params = get_params

    if not method:
      # For lazy
      if self._post_params or self._file_params:
        self._method = "POST"
      else:
        self._method = "GET"
    else:
      self._method = method
    self._encoding = encoding
    self._referer = referer


  def __hash__(self):
    get_kv  = tuple([tuple(param) for param in self._get_params])
    post_kv = tuple([tuple(param) for param in self._post_params])
    file_kv = tuple([tuple(param) for param in self._file_params])

    # TODO: should the referer be in the hash ?
    return hash((self._method, self._resource_path, get_kv, post_kv, file_kv))

  def __eq__(self, other):
    if not isinstance(other, HTTPResource):
      return NotImplemented

    if self._method != other._method:
      return False

    if self._resource_path != other._resource_path:
      return False

    return hash(self) == hash(other)

  def __lt__(self, other):
    if not isinstance(other, HTTPResource):
      return NotImplemented
    if self.url < other.url:
      return True
    else:
      if self.url == other.url:
        return self._encoded_keys() < other._encoded_keys()
      return False

  def __le__(self, other):
    if not isinstance(other, HTTPResource):
      return NotImplemented
    if self.url < other.url:
      return True
    elif self.url == other.url:
      return self._encoded_keys() <= other._encoded_keys()
    return False

  def __ne__(self, other):
    if not isinstance(other, HTTPResource):
      return NotImplemented

    if self._method == other._method:
      return False

    if self._resource_path == other._resource_path:
      return False

    return hash(self) != hash(other)

  def __gt__(self, other):
    if not isinstance(other, HTTPResource):
      return NotImplemented
    if self.url > other.url:
      return True
    elif self.url == other.url:
      return self._encoded_keys() > other._encoded_keys()
    return False

  def __ge__(self, other):
    if not isinstance(other, HTTPResource):
      return NotImplemented
    if self.url > other.url:
      return True
    elif self.url == other.url:
      return self._encoded_keys() >= other._encoded_keys()
    return False

  def _encoded_keys(self):
    quoted_keys = []
    for k, __ in self._post_params:
      k = urllib.quote(k.encode(self._encoding, "ignore"))
      quoted_keys.append(k)
    return "&".join(quoted_keys)

  def __repr__(self):
    buff = ""
    if self._get_params:
      buff= "%s %s" % (self._method, self.url)
    else:
      buff =  "%s %s" % (self._method, self._resource_path)
    if self._post_params:
      buff += "\n\tdata = %s" % (self.encoded_data)
    if self._file_params:
      buff += "\n\tfiles = %s" (self.encoded_files)
    return buff

  def setHeaders(self, response_headers):
    """Set the HTTP headers received while requesting the resource"""
    self._headers = response_headers

  @property
  def url(self):
    if self._get_params:
      return "%s?%s" % (self._resource_path, self._encode_params(self._get_params))
    else:
      return self._resource_path

  @property
  def path(self):
    return self._resource_path

  @property
  def method(self):
    return self._method

  @property
  def encoding(self):
    return self._encoding

  @property
  def headers(self):
    return self._headers

  @property
  def referer(self):
    return self._referer

  # To prevent errors, always return a deepcopy of the internal lists
  @property
  def get_params(self):
    return deepcopy(self._get_params)

  @property
  def post_params(self):
    return deepcopy(self._post_params)

  @property
  def files(self):
    return deepcopy(self._file_params)

  def _encode_params(self, params):
    if not params:
      return ""

    key_values = []
    for k, v in params:
      # for upload fields
      if isinstance(v, tuple):
        v = v[0]
      key_values.append("%s=%s" % (k, v))
    return "&".join(key_values)

  @property
  def encoded_params(self):
    return self._encode_params(self._get_params)

  @property
  def encoded_data(self):
    """Return a raw string of key/value parameters for POST requests"""
    return self._encode_params(self._post_params)

  @property
  def encoded_files(self):
    return self._encode_params(self._file_params)
 

class HTTPResponse(object):
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

class HTTP(object):
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
    
  def send(self, target, method = "", post_params = "", http_headers = {}):
    "Send a HTTP Request. GET or POST (if post_params is set)."
    resp = None
    _headers = {}
    _headers.update(http_headers)

    if not method:
      if post_params:
        method = "POST"
      else:
        method = "GET"

    if isinstance(target, HTTPResource):
      if target.method == "GET":
        resp = self.h.get(target.url, headers = _headers, timeout = self.timeout, allow_redirects = False)
      else:
        _headers.update({'content-type': 'application/x-www-form-urlencoded'})
        if target.referer:
          _headers.update({'referer': target.referer})
        # TODO: For POST use the TooManyRedirects exception instead ?
        resp = self.h.post(target.url, headers = _headers, data = target.encoded_data, timeout = self.timeout, allow_redirects = False)

    else:
      if method == "GET":
        resp = self.h.get(target, headers = _headers, timeout = self.timeout, allow_redirects = False)
      elif method == "POST":
        _headers.update({'content-type': 'application/x-www-form-urlencoded'})
        resp = self.h.post(target, headers = _headers, data = post_params, timeout = self.timeout, allow_redirects = False)
      else:
        resp = self.h.request(method, target, timeout = self.timeout, allow_redirects = False)

    if resp == None:
      return None
    return HTTPResponse(resp, "", datetime.datetime.now())

  def quote(self, url):
    "Encode a string with hex representation (%XX) for special characters."
    return urllib.quote(url)

  def encode(self, params_list): #, encoding = None):
    "Encode a sequence of two-element lists or dictionary into a URL query string."
#    if not encoding:
#      encoding = "ISO-8859-1"
    encoded_params = []
    for k, v in params_list:
#      k = self.quote(k.encode(encoding, "ignore"))
#      v = self.quote(v.encode(encoding, "ignore"))
      encoded_params.append("%s=%s" % (k, v))
    return "&".join(encoded_params)

  def uqe(self, params_list): #, encoding = None):
    "urlencode a string then interpret the hex characters (%41 will give 'A')."
    return urllib.unquote(self.encode(params_list)) #, encoding))

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
