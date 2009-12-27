#!/usr/bin/env python
# -*- coding: UTF-8 -*-

# Wapiti SVN - A web application vulnerability scanner
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

import sys
import getopt
import os
from language.language import Language
lan = Language()
lan.configure()
from net import HTTP
from report.htmlreportgenerator import HTMLReportGenerator
from report.xmlreportgenerator import XMLReportGenerator
from report.txtreportgenerator import TXTReportGenerator


from file.vulnerabilityxmlparser import VulnerabilityXMLParser
from net.crawlerpersister import CrawlerPersister

class Wapiti:
  """
Wapiti-SVN - A web application vulnerability scanner

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

-n <limit>
--nice <limit>
  Define a limit of urls to read with the same pattern
  Use this option to prevent endless loops
  Must be greater than 0

-m <module_options>
--module <module_options>
  Set the modules and HTTP methods to use for attacks.
  Example: -m "-all,xss:get,exec:post"

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

-i <file>
--continue <file>
	This parameter indicates Wapiti to continue with the scan from the specified
  file, this file should contain data from a previous scan.
	The file is optional, if it is not specified, Wapiti takes the default file
  from \"scans\" folder.

-k <file>
--attack <file>
	This parameter indicates Wapiti to perform attacks without scanning again the
  website and following the data of this file.
	The file is optional, if it is not specified, Wapiti takes the default file
  from \"scans\" folder.

-h
--help
	To print this usage message"""

  urls  = {}
  forms = []

  color   = 0
  verbose = 0

  reportGeneratorType = "html"
  REPORT_DIR  = "report"
  REPORT_FILE = "vulnerabilities.xml"
  COPY_REPORT_DIR = "generated_report"
  outputFile = ""

  options = ""

  HTTP = None
  reportGen = None

  attacks = []


  def __init__(self, rooturl):
    self.HTTP = HTTP.HTTP(rooturl)

  def __initReport(self):
    if self.reportGeneratorType.lower() == "xml":
        self.reportGen = XMLReportGenerator()
    elif self.reportGeneratorType.lower() == "html":
        self.reportGen = HTMLReportGenerator()
    elif self.reportGeneratorType.lower() == "txt":
        self.reportGen = TXTReportGenerator()
    else: #default
        self.reportGen = XMLReportGenerator()
    if "__file__" in dir():
      BASE_DIR = os.path.normpath(os.path.join(os.path.abspath(__file__), '..'))
    else:
      BASE_DIR = os.getcwd()
    xmlParser = VulnerabilityXMLParser()
    xmlParser.parse(BASE_DIR + "/config/vulnerabilities/vulnerabilities.xml")
    for vul in xmlParser.getVulnerabilities():
      self.reportGen.addVulnerabilityType(_(vul.getName()), _(vul.getDescription()),
                                          _(vul.getSolution()), vul.getReferences())

  def __initAttacks(self):
    self.__initReport()

    attack = __import__("attack")

    print "[*]", _("Loading modules"), ":"
    print "\t"+ ", ".join(attack.modules)
    for mod_name in attack.modules:
      mod = __import__("attack." + mod_name, fromlist=attack.modules)
      mod_instance = getattr(mod, mod_name)(self.HTTP, self.reportGen)
      if hasattr(mod_instance, "setTimeout"):
        mod_instance.setTimeout(self.HTTP.getTimeOut())
      self.attacks.append(mod_instance)

      self.attacks.sort(lambda a, b: a.PRIORITY - b.PRIORITY)

    for attack in self.attacks:
      attack.setVerbose(self.verbose)
      if self.color == 1:
        attack.setColor()

    if self.options != "":
      opts = self.options.split(",")

      for opt in opts:
        method = ""
        if opt.find(":") > 0:
          module, method = opt.split(":", 1)
        else:
          module = opt

        # desactivate some module options
        if module.startswith("-"):
          module = module[1:]
          if module == "all":
            for x in self.attacks:
              if method == "get" or method == "":
                x.doGET = False
              if method == "post" or method == "":
                x.doPOST = False
          else:
            for x in self.attacks:
              if x.name == module:
                if method == "get" or method == "":
                  x.doGET = False
                if method == "post" or method == "":
                  x.doPOST = False

        # activate some module options
        else:
          if module.startswith("+"):
            module = module[1:]
          if module == "all":
            for x in self.attacks:
              if method == "get" or method == "":
                x.doGET = True
              if method == "post" or method == "":
                x.doPOST = True
          else:
            for x in self.attacks:
              if x.name == module:
                if method == "get" or method == "":
                  x.doGET = True
                if method == "post" or method == "":
                  x.doPOST = True

  def browse(self,crawlerFile):
    "Extract hyperlinks and forms from the webpages found on the website"
    self.urls, self.forms = self.HTTP.browse(crawlerFile)

  def attack(self):
    "Launch the attacks based on the preferences set by the command line"
    if self.urls == {} and self.forms == []:
      print _("No links or forms found in this page !")
      print _("Make sure the url is correct.")
      sys.exit(1)

    self.__initAttacks()

    for x in self.attacks:
      if x.doGET == False and x.doPOST == False:
        continue
      print
      if x.require != []:
        t = [y.name for y in self.attacks if y.name in x.require and (y.doGET or y.doPOST)]
        if x.require != t:
          print "[!]", _("Missing dependecies for module"), x.name , ":"
          print "\t" , ",".join([y for y in x.require if y not in t])
          continue
        else:
          x.loadRequire([y for y in self.attacks if y.name in x.require])

      print "[+]", _("Launching module"), x.name
      x.attack(self.urls, self.forms)

    if self.HTTP.getUploads() != []:
      print "\n" + _("Upload scripts found") + ":"
      print "----------------------"
      for url in self.HTTP.getUploads():
        print url
    if not self.outputFile:
      if self.reportGeneratorType == "html":
        self.outputFile = self.COPY_REPORT_DIR
      else:
        self.outputFile = self.REPORT_FILE
    self.reportGen.generateReport(self.outputFile)
    print "\n" + _("Report")
    print "------"
    print _("A report has been generated in the file") + " " + self.outputFile
    if self.reportGeneratorType == "html":
      print _("Open") + " " + self.outputFile+ \
            "/index.html " + _("with a browser to see this report.")

  def setTimeOut(self, timeout = 6.0):
    "Set the timeout for the time waiting for a HTTP response"
    self.HTTP.setTimeOut(timeout)

  def setProxy(self, proxy = ""):
    "Set a proxy to use for HTTP requests."
    self.HTTP.setProxy(proxy)

  def addStartURL(self, url):
    "Specify an URL to start the scan with. Can be called several times."
    self.HTTP.addStartURL(url)

  def addExcludedURL(self, url):
    "Specify an URL to exclude from the scan. Can be called several times."
    self.HTTP.addExcludedURL(url)

  def setCookieFile(self, cookie):
    "Load session data from a cookie file"
    self.HTTP.setCookieFile(cookie)

  def setAuthCredentials(self, auth_basic):
    "Set credentials to use if the website require an authentification."
    self.HTTP.setAuthCredentials(auth_basic)

  def addBadParam(self, bad_param):
    """Exclude a parameter from an url (urls with this parameter will be
    modified. This function can be call several times"""
    self.HTTP.addBadParam(bad_param)

  def setNice(self, nice):
    """Define how many tuples of parameters / values must be sent for a
    given URL. Use it to prevent infinite loops."""
    self.HTTP.setNice(nice)

  def setScope(self, scope):
    """Set the scope of the crawler for the analysis of the web pages"""
    self.HTTP.setScope(scope)

  def setColor(self):
    "Put colors in the console output (terminal must support colors)"
    self.color = 1

  def verbosity(self, vb):
    "Define the level of verbosity of the output."
    self.verbose = vb
    self.HTTP.verbosity(vb)

  def setModules(self, options = ""):
    """Activate or desactivate (default) all attacks"""
    self.options = options

  def setReportGeneratorType(self, repGentype = "xml"):
    "Set the format of the generated report. Can be xml, html of txt"
    self.reportGeneratorType = repGentype

  def setOutputFile(self, outputFile):
    "Set the filename where the report will be written"
    self.outputFile = outputFile

if __name__ == "__main__":
  doc = _("wapityDoc")
  try:
    prox = ""
    auth = []
    crawlerPersister = CrawlerPersister();
    crawlerFile = None
    attackFile  = None
    if len(sys.argv) < 2:
      print doc
      sys.exit(0)
    if '-h' in sys.argv or '--help' in sys.argv:
      print doc
      sys.exit(0)
    url = sys.argv[1]
    wap = Wapiti(url)
    try:
      opts, args = getopt.getopt(sys.argv[2:], "hup:s:x:c:a:r:v:t:m:o:f:n:kib:",
          ["help", "underline", "proxy=", "start=", "exclude=", "cookie=",
            "auth=", "remove=", "verbose=", "timeout=", "module=",
            "outputfile", "reportType", "nice=", "attack", "continue",
            "scope="])
    except getopt.GetoptError, e:
      print e
      sys.exit(2)
    for o, a in opts:
      if o in ("-h", "--help"):
        print doc
        sys.exit(0)
      if o in ("-s", "--start"):
        if (a.find("http://", 0) == 0) or (a.find("https://", 0) == 0):
          wap.addStartURL(a)
      if o in ("-x", "--exclude"):
        if (a.find("http://", 0) == 0) or (a.find("https://", 0) == 0):
          wap.addExcludedURL(a)
      if o in ("-p", "--proxy"):
          wap.setProxy(a)
      if o in ("-c", "--cookie"):
        wap.setCookieFile(a)
      if o in ("-a", "--auth"):
        if a.find("%") >= 0:
          auth = [a.split("%")[0], a.split("%")[1]]
          wap.setAuthCredentials(auth)
      if o in ("-r", "--remove"):
        wap.addBadParam(a)
      if o in ("-n", "--nice"):
        if str.isdigit(a):
          wap.setNice(int(a))
      if o in ("-u", "--underline"):
        wap.setColor()
      if o in ("-v", "--verbose"):
        if str.isdigit(a):
          wap.verbosity(int(a))
      if o in ("-t", "--timeout"):
        if str.isdigit(a):
          wap.setTimeOut(int(a))
      if o in ("-m", "--module"):
        wap.setModules(a)
      if o in ("-o", "--outputfile"):
        wap.setOutputFile(a)
      if o in ("-f", "--reportType"):
        if (a.find("html", 0) == 0) or (a.find("xml", 0) == 0) \
          or (a.find("txt", 0) == 0):
            wap.setReportGeneratorType(a)
      if o in ("-b", "--scope"):
        wap.setScope(a)
      if o in ("-k", "--attack"):
        attackFile = crawlerPersister.CRAWLER_DATA_DIR + '/' + \
            (url.split("://")[1]).split("/")[0] + '.xml'
      if o in ("-i", "--continue"):
        crawlerFile = crawlerPersister.CRAWLER_DATA_DIR + '/' + \
            (url.split("://")[1]).split("/")[0] + '.xml'
    try:
      opts, args = getopt.getopt(sys.argv[2:], "hup:s:x:c:a:r:v:t:m:o:f:n:k:i:b:",
          ["help", "underline", "proxy=", "start=", "exclude=", "cookie=",
            "auth=", "remove=", "verbose=", "timeout=", "module=",
            "outputfile", "reportType", "nice=", "attack=", "continue=",
            "scope="])
    except getopt.GetoptError, e:
      ""
    for o, a in opts:
      if o in ("-k", "--attack"):
        if a != "" and a[0] != '-':
          attackFile = a
      if o in ("-i", "--continue"):
        if a != '' and a[0] != '-':
          crawlerFile = a
    print _("Wapiti-SVN (wapiti.sourceforge.net)")
    if attackFile != None:
      if crawlerPersister.isDataForUrl(attackFile) == 1:
        crawlerPersister.loadXML(attackFile)
        # TODO: xml structure
        wap.urls  = crawlerPersister.getBrowsed()
        wap.forms = crawlerPersister.getForms()
        # wap.uploads = crawlerPersister.getUploads()
        print _("File") + " " + attackFile + " " + \
            _("loaded, Wapiti will use it to perform the attacks")
      else:
        print _("File") + " " + attackFile + " " + \
            _("not found, Wapiti will scan again the web site")
        wap.browse(crawlerFile)
    else:
      wap.browse(crawlerFile)
    try:
      wap.attack()
    except KeyboardInterrupt:
      print ""
      print _("Attack process interrupted. To perform again the attack, lauch Wapiti with \"-i\" or \"-k\" parameter.")
      print ""
      pass
  except SystemExit:
    pass
