#!/usr/bin/env python

# Wapiti v1.1.8-alpha - A web application vulnerability scanner
# Wapiti Project (http://wapiti.sourceforge.net)
# Copyright (C) 2008 Nicolas Surribas
#
# David del Pozo
# Alberto Pastor
# Informatica Gesfor
# ICT Romulus (http://www.ict-romulus.eu)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

import lswww,urlparse,socket
import sys,re,getopt,os,random
import BeautifulSoup
import XSS, HTTP
from xmlreportgenerator import XMLReportGenerator

class wapiti:
  """
Wapiti-1.1.7-alpha - A web application vulnerability scanner

Usage: python wapiti.py http://server.com/base/url/ [options]

Supported options are:
-s <url>
--start <url>
	To specify an url to start with

-x <url>
--exclude <url>
	To exclude an url from the scan (for example logout scripts)
	You can also use a wildcard (*)
	Exemple : -x "http://server/base/?page=*&module=test"
	or -x http://server/base/admin/* to exclude a directory

-p <url_proxy>
--proxy <url_proxy>
	To specify a proxy
	Exemple: -p http://proxy:port/

-c <cookie_file>
--cookie <cookie_file>
	To use a cookie

-t <timeout>
--timeout <timeout>
	To fix the timeout (in seconds)

-a <login%password>
--auth <login%password>
	Set credentials for HTTP authentication
	Doesn't work with Python 2.4

-r <parameter_name>
--remove <parameter_name>
	Remove a parameter from URLs

-m <module>
--module <module>
	Use a predefined set of scan/attack options
	GET_ALL: only use GET request (no POST)
	GET_XSS: only XSS attacks with HTTP GET method
	POST_XSS: only XSS attacks with HTTP POST method

-u
--underline
	Use color to highlight vulnerables parameters in output

-v <level>
--verbose <level>
	Set the verbosity level
	0: quiet (default), 1: print each url, 2: print every attack

-h
--help
	To print this usage message"""

  root=""
  myls=""
  urls=[]
  forms=[]
  attackedGET=[]
  attackedPOST=[]
  server=""
  proxy={}
  cookie=""
  auth_basic=[]
  color=0
  bad_params=[]
  verbose=0

  doGET=1
  doPOST=1
  doExec=1
  doFileHandling=1
  doInjection=1
  doXSS=1
  doCRLF=1
  timeout=6
  xss_history={}
  GET_XSS={}
  HTTP=None
  XSS=None
  xmlReportGen = None

  #Constants
  SQL_INJECTION = "Sql Injection"
  FILE_HANDLING = "File Handling"
  XSS = "Cross Site Scripting"
  CRLF = "CRLF"
  EXEC = "Commands execution"

  HIGH_LEVEL_VULNERABILITY   = "1"
  MEDIUM_LEVEL_VULNERABILITY = "2"
  LOW_LEVEL_VULNERABILITY    = "3"

  REPORT_DIR = "report"

  def __init__(self,rooturl):
    self.root=rooturl
    self.server=urlparse.urlparse(rooturl)[1]
    self.myls=lswww.lswww(rooturl)
    self.myls.verbosity(1)
    socket.setdefaulttimeout(self.timeout)
    self.__initReport()

  def __initReport(self):
    self.xmlReportGen = XMLReportGenerator()
    self.xmlReportGen.addVulnerabilityType(self.SQL_INJECTION)
    self.xmlReportGen.addVulnerabilityType(self.FILE_HANDLING)
    self.xmlReportGen.addVulnerabilityType(self.XSS)
    self.xmlReportGen.addVulnerabilityType(self.CRLF)
    self.xmlReportGen.addVulnerabilityType(self.EXEC)

  def browse(self):
    self.myls.go()
    self.urls=self.myls.getLinks()
    self.forms=self.myls.getForms()

    self.HTTP=HTTP.HTTP(self.root,self.proxy,self.auth_basic,self.cookie)
    self.XSS=XSS.XSS(self.HTTP)

  def attack(self):
    if self.urls==[]:
      print "Problem scanning website !"
      sys.exit(1)
    if self.doGET==1:
      print "\nAttacking urls (GET)..."
      print  "-----------------------"
      for url in self.urls:
        if url.find("?")!=-1:
          self.attackGET(url)
    if self.doPOST==1:
      print "\nAttacking forms (POST)..."
      print "-------------------------"
      for form in self.forms:
        if form[1]!={}:
          self.attackPOST(form)
    if self.doXSS==1:
      print "\nLooking for permanent XSS"
      print "-------------------------"
      for url in self.urls:
        self.permanentXSS(url)
    if self.myls.getUploads()!=[]:
      print "\nUpload scripts found :"
      print "----------------------"
      for url in self.myls.getUploads():
        print url
    self.xmlReportGen.printToFile(self.REPORT_DIR+"/vulnerabilities.xml")
    print "\nReport"
    print "------"
    print "A report has been generated in the file vulnerabilities.xml"
    print "Open "+self.REPORT_DIR+"/index.html with a browser to see this report."

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

  def setColor(self):
    self.color=1

  def verbosity(self,vb):
    self.verbose=vb
    self.myls.verbosity(vb)

  # following set* functions can be used to create scan modes
  def setGlobal(self,var=0):
    """Activate or desactivate (default) all attacks"""
    self.doGET=var
    self.doPOST=var
    self.doFileHandling=var
    self.doExec=var
    self.doInjection=var
    self.doXSS=var
    self.doCRLF=var

  def setGET(self,get=1):
    self.doGET=get

  def setPOST(self,post=1):
    self.doPOST=post

  def setFileHandling(self,fh=1):
    self.doFileHandling=fh

  def setExec(self,cmds=1):
    self.doExec=cmds

  def setInjection(self,inject=1):
    self.doInjection=inject

  def setXSS(self,xss=1):
    self.doXSS=xss

  def setCRLF(self,crlf=1):
    self.doCRLF=crlf

  def attackGET(self,url):
    page=url.split('?')[0]
    query=url.split('?')[1]
    params=query.split('&')
    dict={}
    if self.verbose==1:
      print "+ attackGET "+url
      print "  ",params
    if query.find("=")>=0:
      for param in params:
        dict[param.split('=')[0]]=param.split('=')[1]
    if self.doFileHandling==1: self.attackFileHandling(page,dict)
    if self.doExec==1: self.attackExec(page,dict)
    if self.doInjection==1: self.attackInjection(page,dict)
    #if self.doXSS==1: self.attackXSS(page,dict)
    if self.doXSS==1: self.new_attackXSS(page,dict)
    if self.doCRLF==1: self.attackCRLF(page,dict)

  def attackPOST(self,form):
    if self.verbose==1:
      print "+ attackPOST "+form[0]
      print "  ",form[1]
    if self.doFileHandling==1: self.attackFileHandling_POST(form)
    if self.doExec==1: self.attackExec_POST(form)
    if self.doInjection==1: self.attackInjection_POST(form)
    if self.doXSS==1: self.attackXSS_POST(form)

  def attackInjection(self,page,dict):
    payload="\xbf'\"("
    if dict=={}:
      err=""
      url=page+"?"+payload
      if url not in self.attackedGET:
        if self.verbose==2:
          print "+ "+url
        data,code=self.HTTP.send(url).getPageCode()
        if data.find("You have an error in your SQL syntax")>=0:
          err="MySQL Injection"
        if data.find("supplied argument is not a valid MySQL")>0:
          err="MySQL Injection"
        if data.find("[Microsoft][ODBC Microsoft Access Driver]")>=0:
          err="Access-Based SQL Injection"
        if data.find("[Microsoft][ODBC SQL Server Driver]")>=0:
          err="MSSQL-Based Injection"
        if data.find("java.sql.SQLException: Syntax error or access violation")>=0:
          err="Java.SQL Injection"
        if data.find("PostgreSQL query failed: ERROR: parser:")>=0:
          err="PostgreSQL Injection"
        if data.find("XPathException")>=0:
          err="XPath Injection"
        if data.find("supplied argument is not a valid ldap")>=0 or data.find("javax.naming.NameNotFoundException")>=0:
          err="LDAP Injection"
        if data.find("DB2 SQL error:")>=0:
          err="DB2 Injection"
        if data.find("Dynamic SQL Error")>=0:
          err="Interbase Injection"
        if data.find("Sybase message:")>=0:
          err="Sybase Injection"
        if err!="":
          self.xmlReportGen.logVulnerability(self.SQL_INJECTION,
                            self.HIGH_LEVEL_VULNERABILITY,
                            url,payload,err+" (QUERY_STRING)")
          print err,"(QUERY_STRING) in",page
          print "\tEvil url:",url
        else:
          if code==500:
            self.xmlReportGen.logVulnerability(self.SQL_INJECTION,
                              self.HIGH_LEVEL_VULNERABILITY,
                              url,payload,"500 HTTP Error code")
            print "500 HTTP Error code with"
            print "\tEvil url:",url
        self.attackedGET.append(url)
    else:
      for k in dict.keys():
        err=""
        tmp=dict.copy()
        tmp[k]=payload
        url=page+"?"+self.HTTP.encode(tmp)
        if url not in self.attackedGET:
          if self.verbose==2:
            print "+ "+url
          data,code=self.HTTP.send(url).getPageCode()
          if data.find("You have an error in your SQL syntax")>=0:
            err="MySQL Injection"
          if data.find("supplied argument is not a valid MySQL")>0:
            err="MySQL Injection"
          if data.find("[Microsoft][ODBC Microsoft Access Driver]")>=0:
            err="Access-Based SQL Injection"
          if data.find("[Microsoft][ODBC SQL Server Driver]")>=0:
            err="MSSQL-Based Injection"
          if data.find("java.sql.SQLException: Syntax error or access violation")>=0:
            err="Java.SQL Injection"
          if data.find("PostgreSQL query failed: ERROR: parser:")>=0:
            err="PostgreSQL Injection"
          if data.find("XPathException")>=0:
            err="XPath Injection"
          if data.find("supplied argument is not a valid ldap")>=0 or data.find("javax.naming.NameNotFoundException")>=0:
            err="LDAP Injection"
          if data.find("DB2 SQL error:")>=0:
            err="DB2 Injection"
          if data.find("Dynamic SQL Error")>=0:
            err="Interbase Injection"
          if data.find("Sybase message:")>=0:
            err="Sybase Injection"
          if err!="":
            if self.color==0:
              self.xmlReportGen.logVulnerability(self.SQL_INJECTION,
                                self.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.encode(tmp),
                                err+" ("+k+")")
              print err,"("+k+") in",page
              print "\tEvil url:",url
            else:
              self.xmlReportGen.logVulnerability(self.SQL_INJECTION,
                                self.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.encode(tmp),
                                err+" : "+url.replace(k+"=","\033[0;31m"+k+"\033[0;0m="))
              print err,":",url.replace(k+"=","\033[0;31m"+k+"\033[0;0m=")
          else:
            if code==500:
              self.xmlReportGen.logVulnerability(self.SQL_INJECTION,
                                self.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.encode(tmp),
                                "500 HTTP Error code")
              print "500 HTTP Error code with"
              print "\tEvil url:",url
          self.attackedGET.append(url)

  def attackFileHandling(self,page,dict):
    payloads=["http://www.google.fr/",
              "/etc/passwd", "/etc/passwd\0", "c:\\\\boot.ini", "c:\\\\boot.ini\0",
              "../../../../../../../../../../etc/passwd", # /.. is similar to / so one such payload is enough :)
              "../../../../../../../../../../etc/passwd\0", # same with null byte
              "../../../../../../../../../../boot.ini",
              "../../../../../../../../../../boot.ini\0"]
    if dict=={}:
      warn=0
      inc=0
      err500=0
      for payload in payloads:
        err=""
        url=page+"?"+self.HTTP.quote(payload)
        if url not in self.attackedGET:
          if self.verbose==2:
            print "+ "+url
          self.attackedGET.append(url)
          if inc==1: continue
          data,code=self.HTTP.send(url).getPageCode()
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
          if err!="":
            self.xmlReportGen.logVulnerability(self.FILE_HANDLING,
                              self.HIGH_LEVEL_VULNERABILITY,
                              url,self.HTTP.quote(payload),
                              str(err)+" (QUERY_STRING) in "+str(page))
            print err,"(QUERY_STRING) in",page
            print "\tEvil url:",url
          else:
            if code==500 and err500==0:
              err500=1
              self.xmlReportGen.logVulnerability(self.FILE_HANDLING,
                                self.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.quote(payload),
                                "500 HTTP Error code")
              print "500 HTTP Error code with"
              print "\tEvil url:",url
    for k in dict.keys():
      warn=0
      inc=0
      err500=0
      for payload in payloads:
        err=""
        tmp=dict.copy()
        tmp[k]=payload
        url=page+"?"+self.HTTP.encode(tmp)
        if url not in self.attackedGET:
          if self.verbose==2:
            print "+ "+url
          self.attackedGET.append(url)
          if inc==1: continue
          data,code=self.HTTP.send(url).getPageCode()
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
          if err!="":
            if self.color==0:
              self.xmlReportGen.logVulnerability(self.FILE_HANDLING,
                                self.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.encode(tmp),err+" ("+k+")")
              print err,"("+k+") in",page
              print "\tEvil url:",url
            else:
              self.xmlReportGen.logVulnerability(self.FILE_HANDLING,
                                self.HIGH_LEVEL_VULNERABILITY,url,self.HTTP.encode(tmp),
                                err+" : "+url.replace(k+"=","\033[0;31m"+k+"\033[0;0m="))
              print err,":",url.replace(k+"=","\033[0;31m"+k+"\033[0;0m=")
          else:
            if code==500 and err500==0:
              err500=1
              self.xmlReportGen.logVulnerability(self.FILE_HANDLING,
                                self.HIGH_LEVEL_VULNERABILITY,url,self.HTTP.encode(tmp),
                                "500 HTTP Error code")
              print "500 HTTP Error code with"
              print "\tEvil url:",url


  def new_attackXSS(self,page,dict):
    # page est l'url de script
    # dict est l'ensembre des variables et leurs valeurs
    if dict=={}:
      err=""
      code="".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for i in range(0,10)]) # don't use upercase as BS make some data lowercase
      url=page+"?"+code
      data=self.HTTP.send(url).getPage()
    else:
      for k in dict.keys():
        err=""
        tmp=dict.copy()
        tmp[k]="__XSS__"
        url=page+"?"+self.HTTP.uqe(tmp)
        if url not in self.attackedGET:
          self.attackedGET.append(url)
          # genere un identifiant unique a rechercher ensuite dans la page
          code="".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for i in range(0,10)]) # don't use upercase as BS make some data lowercase
          tmp[k]=code
          url=page+"?"+self.HTTP.uqe(tmp)
          self.GET_XSS[code]=url
          data=self.HTTP.send(url).getPage()
          # on effectue une recherche rapide sur l'indetifiant
          if data.find(code)>=0:
            # identifiant est dans la page, il faut determiner ou
            if self.XSS.findXSS(data,page,tmp,k,code):
              break

  def attackXSS(self,page,dict):
    if dict=={}:
      # TODO
      err=""
      tab=[page,"QUERYSTRING"]
      xss_hash=hash(str(tab))
      self.xss_history[xss_hash]=tab
      payload="<script>var XSS"
      payload+=str(xss_hash).replace("-","_")
      payload+="</script>"
      url=page+"?"+payload
      if url not in self.attackedGET:
        if self.verbose==2:
          print "+ "+url
        data,code=self.HTTP.send(url).getPageCode()
        if data.find(payload)>=0:
          self.xmlReportGen.logVulnerability(self.XSS,
                            self.HIGH_LEVEL_VULNERABILITY,
                            url,payload,"XSS (QUERY_STRING)")
          print "XSS (QUERY_STRING) in",page
          print "\tEvil url:",url
        else:
          if code==500:
            self.xmlReportGen.logVulnerability(self.XSS,
                              self.HIGH_LEVEL_VULNERABILITY,
                              url,payload,"500 HTTP Error code")
            print "500 HTTP Error code with"
            print "\tEvil url:",url
        self.attackedGET.append(url)
    for k in dict.keys():
      err=""
      tmp=dict.copy()
      tab=[page,k]
      xss_hash=hash(str(tab))
      self.xss_history[xss_hash]=tab
      payload="<script>var XSS"
      payload+=str(xss_hash).replace("-","_")
      payload+=";</script>"
      tmp[k]=payload
      url=page+"?"+self.HTTP.uqe(tmp)
      if url not in self.attackedGET:
        if self.verbose==2:
          print "+ "+url
        data,code=self.HTTP.send(url).getPageCode()
        if data.find(payload)>=0:
          if self.color==0:
            self.xmlReportGen.logVulnerability(self.XSS,
                              self.HIGH_LEVEL_VULNERABILITY,
                              url,self.HTTP.uqe(tmp),
                              "XSS ("+k+")")
            print "XSS ("+k+") in",page
            print "\tEvil url:",url
          else:
            self.xmlReportGen.logVulnerability(self.XSS,
                              self.HIGH_LEVEL_VULNERABILITY,
                              url,self.HTTP.uqe(tmp),
                              "XSS: "+url.replace(k+"=","\033[0;31m"+k+"\033[0;0m="))
            print "XSS",":",url.replace(k+"=","\033[0;31m"+k+"\033[0;0m=")
        else:
          if code==500:
            self.xmlReportGen.logVulnerability(self.XSS,
                              self.HIGH_LEVEL_VULNERABILITY,
                              url,self.HTTP.uqe(tmp),
                              "500 HTTP Error code")
            print "500 HTTP Error code with"
            print "\tEvil url:",url
        self.attackedGET.append(url)

  def attackExec(self,page,dict):
    payloads=["a;env",
              "a);env",
              "/e\0"]
    if dict=={}:
      warn=0
      cmd=0
      err500=0
      for payload in payloads:
        err=""
        url=page+"?"+self.HTTP.quote(payload)
        if url not in self.attackedGET:
          if self.verbose==2:
            print "+ "+url
          self.attackedGET.append(url)
          if cmd==1: continue
          data,code=self.HTTP.send(url).getPageCode()
          if data.find("eval()'d code</b> on line <b>")>=0 and warn==0:
            err="Warning eval()"
            warn=1
          if data.find("PATH=")>=0 and data.find("PWD=")>=0:
            err="Command execution"
            cmd=1
          if data.find("Cannot execute a blank command in")>=0 and warn==0:
            err="Warning exec"
            warn=1
          if data.find("Fatal error</b>:  preg_replace")>=0 and warn==0:
            err="preg_replace injection"
            warn=1
          if err!="":
            self.xmlReportGen.logVulnerability(self.EXEC,self.HIGH_LEVEL_VULNERABILITY,
                              url,self.HTTP.quote(payload),err+" (QUERY_STRING)")
            print err,"(QUERY_STRING) in",page
            print "\tEvil url:",url
          else:
            if code==500 and err500==0:
              err500=1
              self.xmlReportGen.logVulnerability(self.EXEC,self.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.quote(payload),"500 HTTP Error code")
              print "500 HTTP Error code with"
              print "\tEvil url:",url
    for k in dict.keys():
      warn=0
      cmd=0
      err500=0
      for payload in payloads:
        err=""
        tmp=dict.copy()
        tmp[k]=payload
        url=page+"?"+self.HTTP.encode(tmp)
        if url not in self.attackedGET:
          if self.verbose==2:
            print "+ "+url
          self.attackedGET.append(url)
          if cmd==1: continue
          data,code=self.HTTP.send(url).getPageCode()
          if data.find("eval()'d code</b> on line <b>")>=0 and warn==0:
            err="Warning eval()"
            warn=1
          if data.find("PATH=")>=0 and data.find("PWD=")>=0:
            err="Command execution"
            cmd=1
          if data.find("Cannot execute a blank command in")>0 and warn==0:
            err="Warning exec"
            warn=1
          if data.find("Fatal error</b>:  preg_replace")>=0 and warn==0:
            err="preg_replace injection"
            warn=1
          if err!="":
            if self.color==0:
              self.xmlReportGen.logVulnerability(self.EXEC,self.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.encode(tmp),err+" ("+k+")")
              print err,"("+k+") in",page
              print "\tEvil url:",url
            else:
              self.xmlReportGen.logVulnerability(self.EXEC,self.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.encode(tmp),
                                err+" : "+url.replace(k+"=","\033[0;31m"+k+"\033[0;0m="))
              print err,":",url.replace(k+"=","\033[0;31m"+k+"\033[0;0m=")
          else:
            if code==500 and err500==0:
              err500=1
              self.xmlReportGen.logVulnerability(self.EXEC,self.HIGH_LEVEL_VULNERABILITY,
                                url,self.HTTP.encode(tmp),
                                "500 HTTP Error code")
              print "500 HTTP Error code with"
              print "\tEvil url:",url

  # Won't work with PHP >= 4.4.2
  def attackCRLF(self,page,dict):
    payload="http://www.google.fr\r\nWapiti: version 1.1.7-alpha"
    if dict=={}:
      err=""
      url=page+"?"+payload
      if url not in self.attackedGET:
        if self.verbose==2:
          print "+ "+url
        if self.HTTP.send(url).getInfo().has_key('Wapiti'):
          self.xmlReportGen.logVulnerability(self.CRLF,self.HIGH_LEVEL_VULNERABILITY,
                            page,payload,err+" (QUERY_STRING)")
          print "CRLF Injection (QUERY_STRING) in",page
          print "\tEvil url:",url
        self.attackedGET.append(url)
    else:
      for k in dict.keys():
        err=""
        tmp=dict.copy()
        tmp[k]=payload
        url=page+"?"+self.HTTP.encode(tmp)
        if url not in self.attackedGET:
          if self.verbose==2:
            print "+ "+url
          if self.HTTP.send(url).getInfo().has_key('Wapiti'):
            err="CRLF Injection"
            if self.color==0:
              self.xmlReportGen.logVulnerability(self.CRLF,self.HIGH_LEVEL_VULNERABILITY,
                                page,self.HTTP.encode(tmp),err+" ("+k+")")
              print err,"("+k+") in",page
              print "\tEvil url:",url
            else:
              self.xmlReportGen.logVulnerability(self.CRLF,self.HIGH_LEVEL_VULNERABILITY,
                                page,self.HTTP.encode(tmp).
                                err+" : "+url.replace(k+"=","\033[0;31m"+k+"\033[0;0m="))
              print err,":",url.replace(k+"=","\033[0;31m"+k+"\033[0;0m=")
          self.attackedGET.append(url)

  def attackInjection_POST(self,form):
    payload="\xbf'\"("
    page=form[0]
    dict=form[1]
    err=""
    for k in dict.keys():
      tmp=dict.copy()
      tmp[k]=payload
      if (page,tmp) not in self.attackedPOST:
        headers={"Accept": "text/plain"}
        if self.verbose==2:
          print "+ "+page
          print "  ",tmp
        data,code=self.HTTP.send(page,self.HTTP.encode(tmp),headers).getPageCode()
        if data.find("You have an error in your SQL syntax")>=0:
          err="MySQL Injection"
        if data.find("supplied argument is not a valid MySQL")>0:
          err="MySQL Injection"
        if data.find("[Microsoft][ODBC Microsoft Access Driver]")>=0:
          err="Access-Based SQL Injection"
        if data.find("[Microsoft][ODBC SQL Server Driver]")>=0:
          err="MSSQL-Based Injection"
        if data.find("java.sql.SQLException: Syntax error or access violation")>=0:
          err="SQL Injection"
        if data.find("PostgreSQL query failed: ERROR: parser:")>=0:
          err="PostgreSQL Injection"
        if data.find("XPathException")>=0:
          err="XPath Injection"
        if data.find("supplied argument is not a valid ldap")>=0 or data.find("javax.naming.NameNotFoundException")>=0:
          err="LDAP Injection"
        if data.find("DB2 SQL error:")>=0:
          err="DB2 Injection"
        if data.find("Dynamic SQL Error")>=0:
          err="Interbase Injection"
        if data.find("Sybase message:")>=0:
          err="Sybase Injection"
        if err!="":
          self.xmlReportGen.logVulnerability(self.SQL_INJECTION,
                            self.HIGH_LEVEL_VULNERABILITY,
                            page,self.HTTP.encode(tmp),
                            err+" coming from "+form[2])
          print err,"in",page
          print "  with params =",self.HTTP.encode(tmp)
          print "  coming from",form[2]
        else:
          if code==500:
            self.xmlReportGen.logVulnerability(self.SQL_INJECTION,
                              self.HIGH_LEVEL_VULNERABILITY,
                              page,self.HTTP.encode(tmp),
                              "500 HTTP Error coming from "+form[2])
            print "500 HTTP Error code in",page
            print "  with params =",self.HTTP.encode(tmp)
            print "  coming from",form[2]
        self.attackedPOST.append((page,tmp))

  def attackFileHandling_POST(self,form):
    payloads=["http://www.google.fr/",
              "/etc/passwd", "/etc/passwd\0", "c:\\\\boot.ini", "c:\\\\boot.ini\0",
              "../../../../../../../../../../etc/passwd", # /.. is similar to / so one such payload is enough :)
              "../../../../../../../../../../etc/passwd\0", # same with null byte
              "../../../../../../../../../../boot.ini",
              "../../../../../../../../../../boot.ini\0"]
    page=form[0]
    dict=form[1]
    err=""
    for payload in payloads:
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
          if err!="":
            self.xmlReportGen.logVulnerability(self.FILE_HANDLING,
                              self.HIGH_LEVEL_VULNERABILITY,
                              page,self.HTTP.encode(tmp),
                              err+" coming from "+form[2])
            print err,"in",page
            print "  with params =",self.HTTP.encode(tmp)
            print "  coming from",form[2]
          else:
            if code==500 and err500==0:
              err500=1
              self.xmlReportGen.logVulnerability(self.FILE_HANDLING,
                                self.HIGH_LEVEL_VULNERABILITY,
                                page,self.HTTP.encode(tmp),
                                "500 HTTP Error coming from "+form[2])
              print "500 HTTP Error code in",page
              print "  with params =",self.HTTP.encode(tmp)
              print "  coming from",form[2]

  def attackXSS_POST(self,form):
    # TODO : history / attackedPOST
    headers={"Accept": "text/plain"}
    page=form[0]
    dict=form[1]
    for k in dict.keys():
      tmp=dict.copy()

      code="".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for i in range(0,10)]) # don't use upercase as BS make some data lowercase
      tmp[k]=code
      #self.GET_XSS[code]=url
      data=self.HTTP.send(page,self.HTTP.uqe(tmp),headers).getPage()
      # on effectue une recherche rapide sur l'indetifiant
      if data.find(code)>=0:
        # identifiant est dans la page, il faut determiner ou
        if self.XSS.findXSS(data,page,tmp,k,code,form[2]):
          break

        #attention de bloquer les formulaires sans ne prendre en compte la page d'origine
        #mais en se basant seulement sur page cible+params
        #self.attackedPOST.append((page,tmp))

  def attackExec_POST(self,form):
    payloads=["a;env",
              "a);env",
              "/e\0"]
    page=form[0]
    dict=form[1]
    err=""
    for payload in payloads:
      warn=0
      cmd=0
      err500=0
      for k in dict.keys():
        tmp=dict.copy()
        tmp[k]=payload
        if (page,tmp) not in self.attackedPOST:
          self.attackedPOST.append((page,tmp))
          if cmd==1: continue
          headers={"Accept": "text/plain"}
          if self.verbose==2:
            print "+ "+page
            print "  ",tmp
          data,code=self.HTTP.send(page,self.HTTP.encode(tmp),headers).getPageCode()
          if data.find("eval()'d code</b> on line <b>")>=0 and warn==0:
            err="Warning eval()"
            warn=1
          if data.find("PATH=")>=0 and data.find("PWD=")>=0:
            err="Command execution"
            cmd=1
          if data.find("Cannot execute a blank command in")>0 and warn==0:
            err="Warning exec"
            warn=1
          if data.find("Fatal error</b>:  preg_replace")>=0 and warn==0:
            err="preg_replace injection"
            warn=1
          if err!="":
            self.xmlReportGen.logVulnerability(self.XSS,self.HIGH_LEVEL_VULNERABILITY,
                              page,self.HTTP.encode(tmp),
                              err+" coming from "+form[2])
            print err,"in",page
            print "  with params =",self.HTTP.encode(tmp)
            print "  coming from",form[2]
          else:
            if code==500 and err500==0:
              err500=1
              self.xmlReportGen.logVulnerability(self.XSS,self.HIGH_LEVEL_VULNERABILITY,
                                page,self.HTTP.encode(tmp),
                                "500 HTTP Error code coming from "+form[2])
              print "500 HTTP Error code in",page
              print "  with params =",self.HTTP.encode(tmp)
              print "  coming from",form[2]

  def permanentXSS(self,url):
    data=self.HTTP.send(url).getPage()
    for code in self.GET_XSS.keys():
      if data.find(code):
        if self.XSS.validXSS(data,code):
          print "Found permanent XSS with ",self.GET_XSS[code].replace(code,"<XSS>")
          self.xmlReportGen.logVulnerability(self.XSS,
                            self.HIGH_LEVEL_VULNERABILITY,url,"",
                            "Found permanent XSS with "+self.GET_XSS[code].replace(code,"<XSS>"))
    # TODO
    p=re.compile("<script>var XSS[_]?[0-9]{9,10};</script>")
    for s in p.findall(data):
      s=s.split(";")[0].split('XSS')[1].replace("_","-")
      if self.xss_history.has_key(int(s)):
        self.xmlReportGen.logVulnerability(self.XSS,
                          self.HIGH_LEVEL_VULNERABILITY,url,"",
                          "Found permanent XSS attacked by "+self.xss_history[int(s)][0]+
                          " with field "+self.xss_history[int(s)][1])
        print "Found permanent XSS in",url
        print "  attacked by",self.xss_history[int(s)][0],"with field",self.xss_history[int(s)][1]

class GetTheFuckOutOfMyLoop(Exception): pass

if __name__ == "__main__":
  try:
    prox={}
    auth=[]
    if len(sys.argv)<2:
      print wapiti.__doc__
      sys.exit(0)
    if '-h' in sys.argv or '--help' in sys.argv:
      print wapiti.__doc__
      sys.exit(0)
    wap=wapiti(sys.argv[1])
    try:
      opts, args = getopt.getopt(sys.argv[2:], "hup:s:x:c:a:r:v:t:m:",
          ["help","underline","proxy=","start=","exclude=","cookie=","auth=","remove=","verbose=","timeout=","module="])
    except getopt.GetoptError,e:
      print e
      sys.exit(2)
    for o,a in opts:
      if o in ("-h", "--help"):
        print wapiti.__doc__
        sys.exit(0)
      if o in ("-s","--start"):
        if (a.find("http://",0)==0) or (a.find("https://",0)==0):
          wap.addStartURL(a)
      if o in ("-x","--exclude"):
        if (a.find("http://",0)==0) or (a.find("https://",0)==0):
          wap.addExcludedURL(a)
      if o in ("-p","--proxy"):
        if (a.find("http://",0)==0) or (a.find("https://",0)==0):
          prox={'http':a}
          wap.setProxy(prox)
      if o in ("-c","--cookie"):
        wap.setCookieFile(a)
      if o in ("-a","--auth"):
        if a.find("%")>=0:
          auth=[a.split("%")[0],a.split("%")[1]]
          wap.setAuthCredentials(auth)
      if o in ("-r","--remove"):
        wap.addBadParam(a)
      if o in ("-u","--underline"):
        wap.setColor()
      if o in ("-v","--verbose"):
        if str.isdigit(a):
          wap.verbosity(int(a))
      if o in ("-t","--timeout"):
        if str.isdigit(a):
          wap.setTimeOut(int(a))
      if o in ("-m","--module"):
        if a=="GET_XSS":
          wap.setGlobal()
          wap.setGET()
          wap.setXSS()
        elif a=="POST_XSS":
          wap.setGlobal()
          wap.setPOST()
          wap.setXSS()
        elif a=="GET_ALL":
          wap.setPOST(0)
        elif a=="POST_ALL":
          wap.setGET(0)
        elif a=="GET_FILE":
          wap.setGlobal()
          wap.setGET()
          wap.setFileHandling()
    print "Wapiti-1.1.8-alpha (wapiti.sourceforge.net)"
    print "THIS IS AN ALPHA VERSION - PLEASE REPORT BUGS"
    wap.browse()
    wap.attack()
  except SystemExit:
    pass
