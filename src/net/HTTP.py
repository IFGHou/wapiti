#!/usr/bin/env python
import lswww, urllib, urllib2, urlparse, socket, os
import cgi
import httplib2

class HTTPResponse:
  data=""
  code=200
  headers={}

  def __init__(self,data,code,headers):
    self.data=data
    self.code=code
    self.headers=headers

  def getPage(self):
    return self.data

  def getCode(self):
    return self.code

  def getInfo(self):
    return self.headers

  def getPageCode(self):
    return (self.data,self.code)

class HTTP:
  root=""
  myls=""
  server=""
  cookie=""
  proxy=""
  auth_basic=[]
  timeout=6
  h=None
  global_headers={}

  def __init__(self,root):
    self.root=root
    self.server=urlparse.urlparse(root)[1]
    self.myls=lswww.lswww(root)
    self.myls.verbosity(1)
    socket.setdefaulttimeout(self.timeout)

  def browse(self):
    self.myls.go()
    urls  = self.myls.getLinks()
    forms = self.myls.getForms()

    # HttpLib2 vars
    proxy=None

    if self.proxy!="":
      (proxy_type, proxy_usr, proxy_pwd, proxy_host, proxy_port, path, query, fragment)=httplib2.parse_proxy(self.proxy)
      proxy=httplib2.ProxyInfo(proxy_type, proxy_host, proxy_port, proxy_user=proxy_usr, proxy_pass=proxy_pwd)

    try:
      import cookielib
    except ImportError:
      pass
    else:
      if self.cookie!="":
        cj = cookielib.LWPCookieJar()
        if os.path.isfile(self.cookie):
          cj.load(self.cookie,ignore_discard=True)
          # "Cookie" is sent lowercase... have to check why
          self.global_headers["Cookie"]="; ".join(cook.name+"="+cook.value for cook in cj)

    self.h=httplib2.Http(cache=None,timeout=self.timeout,proxy_info=proxy)

    if self.auth_basic!=[]:
      self.h.add_credentials(self.auth_basic[0], self.auth_basic[1])

    return urls, forms

  def getUploads(self):
    return self.myls.getUploads()

  def send(self,target,post_data=None,http_headers={}):
    data=""
    code=0
    info={}
    _headers=self.global_headers
    _headers.update(http_headers)
    if post_data==None:
      info,data=self.h.request(target, headers=_headers)
    else:
      _headers.update({'Content-type': 'application/x-www-form-urlencoded'})
      info,data=self.h.request(target, "POST", headers=_headers, body=post_data)
    code=info['status']
    return HTTPResponse(data,code,info)

  def quote(self,url):
    return urllib.quote(url)

  def encode(self,url):
    return urllib.urlencode(url)

  def uqe(self,url):
    return urllib.unquote(urllib.urlencode(url))

  def escape(self,url):
    return cgi.escape(url)

  def setTimeOut(self,timeout=6):
    self.timeout=timeout
    self.myls.setTimeOut(timeout)

  def setProxy(self,proxy=""):
    self.proxy=proxy
    self.myls.setProxy(proxy)

  def addStartURL(self,url):
    self.myls.addStartURL(url)

  def addExcludedURL(self,url):
    self.myls.addExcludedURL(url)

  def setCookieFile(self,cookie):
    self.cookie=cookie
    self.myls.setCookieFile(cookie)

  def setAuthCredentials(self,auth_basic):
    self.auth_basic=auth_basic
    self.myls.setAuthCredentials(auth_basic)

  def addBadParam(self,bad_param):
    self.myls.addBadParam(bad_param)

  def setNice(self,nice=0):
    self.myls.setNice(nice)

  def verbosity(self,vb):
    self.myls.verbosity(vb)

