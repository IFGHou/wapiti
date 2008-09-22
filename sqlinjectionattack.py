from attack import Attack
from vulnerability import Vulnerability

class SQLInjectionAttack(Attack):

  def __init__(self,HTTP,xmlRepGenerator):
    Attack.__init__(self,HTTP,xmlRepGenerator)

  def __findPatternInResponse(self,data):
    if data.find("You have an error in your SQL syntax")>=0:
      return "MySQL Injection"
    if data.find("supplied argument is not a valid MySQL")>0:
      return "MySQL Injection"
    if data.find("[Microsoft][ODBC Microsoft Access Driver]")>=0:
      return "Access-Based SQL Injection"
    if data.find("[Microsoft][ODBC SQL Server Driver]")>=0:
      return "MSSQL-Based Injection"
    if data.find("java.sql.SQLException: Syntax error or access violation")>=0:
      return "Java.SQL Injection"
    if data.find("PostgreSQL query failed: ERROR: parser:")>=0:
      return "PostgreSQL Injection"
    if data.find("XPathException")>=0:
      return "XPath Injection"
    if data.find("supplied argument is not a valid ldap")>=0 or data.find("javax.naming.NameNotFoundException")>=0:
      return "LDAP Injection"
    if data.find("DB2 SQL error:")>=0:
      return "DB2 Injection"
    if data.find("Dynamic SQL Error")>=0:
      return "Interbase Injection"
    if data.find("Sybase message:")>=0:
      return "Sybase Injection"
    return ""

  def attackGET(self,page,dict,attackedGET):
    payload="\xbf'\"("
    if dict=={}:
      err=""
      url=page+"?"+payload
      if url not in attackedGET:
        if self.verbose==2:
          print "+ "+url
        data,code=self.HTTP.send(url).getPageCode()
        err = self.__findPatternInResponse(data)
        if err!="":
          self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                            url,payload,err+" (QUERY_STRING)")
          print err,"(QUERY_STRING) in",page
          print "\tEvil url:",url
        else:
          if code==500:
            self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              url,payload,"500 HTTP Error code")
            print "500 HTTP Error code with"
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
          data,code=self.HTTP.send(url).getPageCode()
          err = self.__findPatternInResponse(data)
          if err!="":
            if self.color==0:
              self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.encode(tmp),
                                err+" ("+k+")")
              print err,"("+k+") in",page
              print "\tEvil url:",url
            else:
              self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.encode(tmp),
                                err+" : "+url.replace(k+"=","\033[0;31m"+k+"\033[0;0m="))
              print err,":",url.replace(k+"=","\033[0;31m"+k+"\033[0;0m=")
          else:
            if code==500:
              self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                                Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.encode(tmp),
                                "500 HTTP Error code")
              print "500 HTTP Error code with"
              print "\tEvil url:",url
          attackedGET.append(url)

  def attackPOST(self,form,attackedPOST):
    payload="\xbf'\"("
    page=form[0]
    dict=form[1]
    err=""
    for k in dict.keys():
      tmp=dict.copy()
      tmp[k]=payload
      if (page,tmp) not in attackedPOST:
        headers={"Accept": "text/plain"}
        if self.verbose==2:
          print "+ "+page
          print "  ",tmp
        data,code=self.HTTP.send(page,self.HTTP.encode(tmp),headers).getPageCode()
        err = self.__findPatternInResponse(data)
        if err!="":
          self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                            Vulnerability.HIGH_LEVEL_VULNERABILITY,
                            page,self.HTTP.encode(tmp),
                            err+" coming from "+form[2])
          print err,"in",page
          print "  with params =",self.HTTP.encode(tmp)
          print "  coming from",form[2]
        else:
          if code==500:
            self.reportGen.logVulnerability(Vulnerability.SQL_INJECTION,
                              Vulnerability.HIGH_LEVEL_VULNERABILITY,
                              page,self.HTTP.encode(tmp),
                              "500 HTTP Error coming from "+form[2])
            print "500 HTTP Error code in",page
            print "  with params =",self.HTTP.encode(tmp)
            print "  coming from",form[2]
        attackedPOST.append((page,tmp))

