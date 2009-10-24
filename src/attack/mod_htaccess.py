#!/usr/bin/env python
#
# Authors:
# Anthony DUBOCAGE
# Guillaume TRANCHANT
# Gregory FONTAINE

from attack import Attack
from vulnerability import Vulnerability
from vulnerabilitiesdescriptions import VulnerabilitiesDescriptions as VulDescrip

class mod_htaccess(Attack):
  """
  This class implements a htaccess attack
  """	

  name = "htaccess"

  doGET = False
  doPOST = False

  def __init__(self, HTTP, xmlRepGenerator):
    Attack.__init__(self, HTTP, xmlRepGenerator)
    
  #this function return code signification when htaccess protection enabled
  def __returnErrorByCode(self, code):
    err = ""
    if code == "401":
      err = "Authorization Required"
    elif code == "402":
      err = "Payment Required"
    elif code == "403":
      err = "Forbidden"
    else:
      err = "ok"
    return err


  def attackGET(self, page, dict, headers = {}):
    err = ""
    url = page
    err500 = 0
    if url not in self.attackedGET:
      #print the url if verbose equal 2
      if self.verbose == 2:
        print "+ " + url
      
      err1 = self.__returnErrorByCode(headers["status"])
      
      if err1 != "ok":
        data1 = self.HTTP.send(url).getPage()
        #htaccess protection detected
        if self.color == 1:
          print self.RED + "/!\ Found HtAccess protection : ", url + self.STD
        else:
          print "/!\ Found HtAccess protection : ", url

        
        data2, code2 = self.HTTP.send(url, method = "ABC").getPageCode()
        err2 = self.__returnErrorByCode(code2)
        
        
        if err2 == "ok":
          #htaccess bypass success
          
          #print output informations by verbosity option
          if self.verbose >= 1:
            if self.color == 1:
              print self.CYAN + "|HTTP Code : ", headers["status"], ":", err1 + self.STD
            else:
              print "|HTTP Code : ", headers["status"], ":", err1

          if self.verbose == 2:
            if self.color == 1:
              print self.YELLOW + "Code source :" + self.STD
              print self.GB + data1 + self.STD
            else:
              print "Code source :"
              print data1
          
          #report xml generator (ROMULUS) not implemented for htaccess
          self.reportGen.logVulnerability(Vulnerability.HTACCESS, Vulnerability.HIGH_LEVEL_VULNERABILITY, url,"",err+" HtAccess")
          if self.color ==1:
            print self.RED + "\t.htaccess bypass : ", url + self.STD
          else:
            print "\t.htaccess bypass : ", url

          #print output informations by verbosity option
          if self.verbose >= 1:
            if self.color ==1:
              print self.CYAN + "|HTTP Code : ", code2 + self.STD
            else:
              print "|HTTP Code : ", code2

          if self.verbose == 2:
            if self.color == 1:
              print self.YELLOW + "Code source :" + self.STD
              print self.GB + data2 + self.STD
            else:
              print "Code source :"
              print data2

        else:
          if code1 == 500 and err500 == 0:
            err500 = 1
            self.reportGen.logVulnerability(Vulnerability.EXEC, Vulnerability.HIGH_LEVEL_VULNERABILITY, url, "", VulDescrip.ERROR_500+"<br>"+VulDescrip.ERROR_500_DESCRIPTION)
            print "500 HTTP Error code with"
            print "\tEvil url:", url
            
          #add the url with the url attacked
        self.attackedGET.append(url)

