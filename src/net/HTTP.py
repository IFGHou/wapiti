#!/usr/bin/env python
import lswww,urllib,urllib2,urlparse,socket,os

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
  proxy={}
  auth_basic=[]
  timeout=6

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
    director = urllib2.OpenerDirector()

    director.add_handler(urllib2.HTTPHandler())
    director.add_handler(urllib2.HTTPSHandler())

    try:
      import cookielib
    except ImportError:
      pass
    else:
      if self.cookie!="":
        cj = cookielib.LWPCookieJar()
        if os.path.isfile(self.cookie):
          cj.load(self.cookie,ignore_discard=True)
          director.add_handler(urllib2.HTTPCookieProcessor(cj))

    if self.proxy!={}:
      director.add_handler(urllib2.ProxyHandler(self.proxy))

    if self.auth_basic!=[]:
      passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
      passman.add_password(None, self.root, self.auth_basic[0], self.auth_basic[1])
      director.add_handler(urllib2.HTTPBasicAuthHandler(passman))

    urllib2.install_opener(director)

    return urls, forms

  def getUploads(self):
    return self.myls.getUploads()

  def send(self,target,post_data=None,http_headers={}):
    data=""
    code=0
    info={}
    try:
      req = urllib2.Request(target,post_data,http_headers)
      u = urllib2.urlopen(req)
      data=u.read()
      code=u.code
      info=u.info()
    except (urllib2.URLError,socket.timeout),e:
      if hasattr(e,'code'):
        data=""
    return HTTPResponse(data,code,info)

  def quote(self,url):
    return urllib.quote(url)

  def encode(self,url):
    return urllib.urlencode(url)

  def uqe(self,url):
    return urllib.unquote(urllib.urlencode(url))

  def setTimeOut(self,timeout=6):
    self.timeout=timeout
    self.myls.setTimeOut(timeout)

  def setProxy(self,proxy={}):
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

