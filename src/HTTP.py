#!/usr/bin/env python
import lswww,urllib,urllib2,urlparse,socket

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
  cookielibhere=0

  def __init__(self,root,proxy={},auth=[],cookie=""):
    try:
      import cookielib
    except ImportError:
      pass
    else:
      self.cookielibhere=1

    director = urllib2.OpenerDirector()

    director.add_handler(urllib2.HTTPHandler())
    director.add_handler(urllib2.HTTPSHandler())

    if cookie!="" and self.cookielibhere==1:
      cj = cookielib.LWPCookieJar()
      if os.path.isfile(cookie):
        cj.load(cookie,ignore_discard=True)
        director.add_handler(urllib2.HTTPCookieProcessor(cj))

    if proxy!={}:
      director.add_handler(urllib2.ProxyHandler(proxy))

    if auth!=[]:
      passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
      passman.add_password(None, root, auth[0], auth[1])
      director.add_handler(urllib2.HTTPBasicAuthHandler(passman))

    urllib2.install_opener(director)

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

