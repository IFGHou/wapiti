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

import sys,re,getopt,os
import urlparse,socket
from net import lswww
from net import BeautifulSoup
from net import HTTP
from report.htmlreportgenerator import HTMLReportGenerator 
from report.xmlreportgenerator import XMLReportGenerator
from attack.sqlinjectionattack import SQLInjectionAttack
from attack.filehandlingattack import FileHandlingAttack
from attack.execattack import ExecAttack
from attack.crlfattack import CRLFAttack
from attack.xssattack import XSSAttack
from vulnerability import Vulnerability
from vulnerabilityxmlparser import VulnerabilityXMLParser
from vulnerabilityxmlparser import Vulnerability

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
	Example : -x "http://server/base/?page=*&module=test"
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

-f <type_file>
--reportType <type_file>
	Set the type of the report
	xml: Report in XML format
	html: Report in HTML format
	
-o <output>
--output <output_file>
	Set the name of the report file
	If the selected report type is "html", this parameter must be a directory
	
-h
--help
	To print this usage message"""

  urls  = []
  forms = []
  attackedGET  = []
  attackedPOST = []

  color   = 0
  verbose = 0

  reportGeneratorType = "html"
  REPORT_DIR  = "report"
  REPORT_FILE = "vulnerabilities.xml"
  COPY_REPORT_DIR = "generated_report"
  outputFile = ""

  doGET=1
  doPOST=1
  doExec=1
  doFileHandling=1
  doInjection=1
  doXSS=1
  doCRLF=1

  HTTP=None
  reportGen = None

  xssAttack          = None
  sqlInjectionAttack = None
  fileHandlingAttack = None
  execAttack         = None
  crlfAttack         = None
  attacks = []


  def __init__(self,rooturl):
    self.HTTP = HTTP.HTTP(rooturl)

  def __initReport(self):
    if self.reportGeneratorType.lower() == "xml":
        self.reportGen = XMLReportGenerator()
    elif self.reportGeneratorType.lower() == "html":
        self.reportGen = HTMLReportGenerator()
    else: #default
        self.reportGen = XMLReportGenerator()
    BASE_DIR = os.path.normpath(os.path.join(os.path.abspath(__file__),'..'))
    xmlParser = VulnerabilityXMLParser()
    xmlParser.parse(BASE_DIR+"/config/vulnerabilities/vulnerabilities.xml")
    for vul in xmlParser.getVulnerabilities():
      self.reportGen.addVulnerabilityType(vul.getName(),vul.getDescription(),vul.getSolution(),vul.getReferences())

  def __initAttacks(self):
    self.__initReport()
    self.sqlInjectionAttack = SQLInjectionAttack(self.HTTP,self.reportGen)
    self.fileHandlingAttack = FileHandlingAttack(self.HTTP,self.reportGen)
    self.execAttack         = ExecAttack        (self.HTTP,self.reportGen)
    self.crlfAttack         = CRLFAttack        (self.HTTP,self.reportGen)
    self.xssAttack          = XSSAttack         (self.HTTP,self.reportGen)
    self.attacks = [self.sqlInjectionAttack, self.fileHandlingAttack,
                    self.execAttack, self.crlfAttack, self.xssAttack]
    for attack in self.attacks:
      attack.setVerbose(self.verbose)
      if self.color == 1:
        attack.setColor()

  def browse(self):
    self.urls,self.forms = self.HTTP.browse()

  def attack(self):
    if self.urls==[] and self.forms==[]:
      print "Problem scanning website !"
      sys.exit(1)

    self.__initAttacks()

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
        self.xssAttack.permanentXSS(url)
    if self.HTTP.getUploads()!=[]:
      print "\nUpload scripts found :"
      print "----------------------"
      for url in self.HTTP.getUploads():
        print url
    if not self.outputFile:
      if self.reportGeneratorType == "html":
        self.outputFile = self.COPY_REPORT_DIR
      else:
        self.outputFile = self.REPORT_FILE
    self.reportGen.generateReport(self.outputFile)
    print "\nReport"
    print "------"
    print "A report has been generated in the file "+ self.outputFile
    if self.reportGeneratorType == "html":
      print "Open "+self.outputFile+"/index.html with a browser to see this report."

  def setTimeOut(self,timeout=6):
    self.HTTP.setTimeOut(timeout)

  def setProxy(self,proxy={}):
    self.HTTP.setProxy(proxy)

  def addStartURL(self,url):
    self.HTTP.addStartURL(url)

  def addExcludedURL(self,url):
    self.HTTP.addExcludedURL(url)

  def setCookieFile(self,cookie):
    self.HTTP.setCookieFile(cookie)

  def setAuthCredentials(self,auth_basic):
    self.HTTP.setAuthCredentials(auth_basic)

  def addBadParam(self,bad_param):
    self.HTTP.addBadParam(bad_param)

  def setColor(self):
    self.color=1

  def verbosity(self,vb):
    self.verbose=vb
    self.HTTP.verbosity(vb)

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

  def setReportGeneratorType(self,repGentype="xml"):
    self.reportGeneratorType = repGentype

  def setOutputFile(self,outputFile):
    self.outputFile = outputFile

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
    if self.doFileHandling==1: self.fileHandlingAttack.attackGET(page,dict,self.attackedGET)
    if self.doExec==1:         self.execAttack        .attackGET(page,dict,self.attackedGET)
    if self.doInjection==1:    self.sqlInjectionAttack.attackGET(page,dict,self.attackedGET)
    if self.doXSS==1:          self.xssAttack         .attackGET(page,dict,self.attackedGET)
    if self.doCRLF==1:         self.crlfAttack        .attackGET(page,dict,self.attackedGET)

  def attackPOST(self,form):
    if self.verbose==1:
      print "+ attackPOST "+form[0]
      print "  ",form[1]
    if self.doFileHandling==1: self.fileHandlingAttack.attackPOST(form,self.attackedPOST)
    if self.doExec==1:         self.execAttack        .attackPOST(form,self.attackedPOST)
    if self.doInjection==1:    self.sqlInjectionAttack.attackPOST(form,self.attackedPOST)
    if self.doXSS==1:          self.xssAttack         .attackPOST(form,self.attackedPOST)


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
      opts, args = getopt.getopt(sys.argv[2:], "hup:s:x:c:a:r:v:t:m:o:f:",
          ["help","underline","proxy=","start=","exclude=","cookie=","auth=","remove=","verbose=","timeout=","module=", "outputfile", "reportType"])
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
      if o in ("-o","--outputfile"):
        wap.setOutputFile(a)
      if o in ("-f","--reportType"):
        if (a.find("html",0)==0) or (a.find("xml",0)==0):
          wap.setReportGeneratorType(a)
    print "Wapiti-1.1.8-alpha (wapiti.sourceforge.net)"
    print "THIS IS AN ALPHA VERSION - PLEASE REPORT BUGS"
    wap.browse()
    wap.attack()
  except SystemExit:
    pass
