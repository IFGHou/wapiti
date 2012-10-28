#!/usr/bin/env python
# -*- coding: UTF-8 -*-

# XML Report Generator Module for Wapiti Project
# Wapiti Project (http://wapiti.sourceforge.net)
#
# David del Pozo
# Alberto Pastor
# Copyright (C) 2008 Informatica Gesfor
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

from xml.dom.minidom import Document
from reportgenerator import ReportGenerator
import net.HTTP
import datetime

WAPITI_VERSION = "Wapiti SVN";

def isPeerAddrPort(p):
  """Is p a (str,int) tuple? I.E. an (ip_address,port)"""
  if type(p)==tuple and len(p)==2:
    return type(p[0])==str and type(p[1])==int
  else:
    return False

class XMLReportGenerator(ReportGenerator):
    """
    This class generates a report with the method printToFile(fileName) which contains
    the information of all the vulnerabilities notified to this object through the 
    method logVulnerability(vulnerabilityTypeName,level,url,parameter,info).
    The format of the file is XML and it has the following structure:
    <report type="security">
        <generatedBy id="Wapiti SVN"/>
            <bugTypeList>
                <bugType name="SQL Injection">
                    <bugList/>

    <report>
        <vulnerabilityTypeList>
            <vulnerabilityType name="SQL Injection">
                <vulnerabilityList>
                    <vulnerability level="3">
                        <url>http://www.a.com</url>
                        <parameters>id=23</parameters>
                        <info>SQL Injection</info>
                    </vulnerability>
                </vulnerabilityList>
            </vulnerablityType>
        </vulnerabilityTypeList>
    </report>
    """

    __xmlDoc = None
    __vulnerabilityTypeList = None

    def __init__(self):
        self.__xmlDoc = Document()
        report = self.__addReport()
        generated = self.__xmlDoc.createElement("generatedBy")
        generated.setAttribute("id", WAPITI_VERSION);
        report.appendChild(generated)
        self.__vulnerabilityTypeList = self.__xmlDoc.createElement("bugTypeList")
        report.appendChild(self.__vulnerabilityTypeList)

    def __addReport(self):
        report = self.__xmlDoc.createElement("report")
        report.setAttribute("type", "security")
        self.__xmlDoc.appendChild(report)
        return report

    def __addToVulnerabilityTypeList(self,vulnerabilityType):
        self.__vulnerabilityTypeList.appendChild(vulnerabilityType)

    def addVulnerabilityType(self, name, description = "", solution = "", references = {}):
        """
        This method adds a vulnerability type, it can be invoked to include in the
        report the type. 
        The types are not stored previously, they are added when the method 
        logVulnerability(vulnerabilityTypeName,level,url,parameter,info) is invoked
        and if there is no vulnerabilty of a type, this type will not be presented
        in the report
        """
        vulnerabilityType = self.__xmlDoc.createElement("bugType")
        vulnerabilityType.setAttribute("name", name)
        vulnerabilityType.appendChild(self.__xmlDoc.createElement("bugList"))
        self.__addToVulnerabilityTypeList(vulnerabilityType)
        if description != "":
          descriptionNode = self.__xmlDoc.createElement("description")
          descriptionNode.appendChild(self.__xmlDoc.createCDATASection(description))
          vulnerabilityType.appendChild(descriptionNode)
        if solution != "":
          solutionNode = self.__xmlDoc.createElement("solution")
          solutionNode.appendChild(self.__xmlDoc.createCDATASection(solution))
          vulnerabilityType.appendChild(solutionNode)
        if references != "":
          referencesNode = self.__xmlDoc.createElement("references")
          for ref in references:
            referenceNode = self.__xmlDoc.createElement("reference")
            titleNode = self.__xmlDoc.createElement("title")
            urlNode = self.__xmlDoc.createElement("url")
            titleNode.appendChild(self.__xmlDoc.createTextNode(ref))
            urlNode.appendChild(self.__xmlDoc.createTextNode(references[ref]))
            referenceNode.appendChild(titleNode)
            referenceNode.appendChild(urlNode)
            referencesNode.appendChild(referenceNode)
          vulnerabilityType.appendChild(referencesNode)
        return vulnerabilityType

    def __addToVulnerabilityList(self,vulnerabilityTypeName,vulnerability):
        vulnerabilityType = None
        for node in self.__vulnerabilityTypeList.childNodes:
            if node.nodeType == node.ELEMENT_NODE and node.getAttribute("name") == vulnerabilityTypeName:
                vulnerabilityType = node
                break
        if vulnerabilityType == None:
            vulnerabilityType = self.addVulnerabilityType(vulnerabilityTypeName)
        vulnerabilityType.childNodes[0].appendChild(vulnerability)

    def logVulnerability(self,vulnerabilityTypeName, level, url, parameter, info, resp=None):
        """
        Store the information about the vulnerability to be printed later.
        The method printToFile(fileName) can be used to save in a file the
        vulnerabilities notified through the current method.
        """

        if resp==None:
          peer=None
          ts=datetime.datetime.now()
        elif issubclass(resp.__class__, requests.exceptions.Timeout):
          peer = resp.peer
          ts = resp.timestamp
        elif issubclass(resp.__class__, net.HTTP.HTTPResponse):
          peer = resp.peer
          ts = resp.timestamp
        else:
          raise TypeError(resp)
        
        vulnerability = self.__xmlDoc.createElement("bug")
        vulnerability.setAttribute("level", level)
        
        tsNode = self.__xmlDoc.createElement("timestamp")
        tsNode.appendChild(self.__xmlDoc.createTextNode(ts.isoformat()))
        vulnerability.appendChild(tsNode)
        
        urlNode = self.__xmlDoc.createElement("url")
        urlNode.appendChild(self.__xmlDoc.createTextNode(url))
        vulnerability.appendChild(urlNode)
        
        if peer!=None:
          peerNode = self.__xmlDoc.createElement("peer")
          if isPeerAddrPort(peer):
            addrNode = self.__xmlDoc.createElement("addr")
            addrNode.appendChild( self.__xmlDoc.createTextNode(peer[0]) )
            peerNode.appendChild(addrNode)
          
            portNode = self.__xmlDoc.createElement("port")
            portNode.appendChild( self.__xmlDoc.createTextNode(str(peer[1])) )
            peerNode.appendChild(portNode)
          else:
            addrNode = self.__xmlDoc.createElement("addr")
            addrNode.appendChild( self.__xmlDoc.createTextNode(str(peer)) )
            peerNode.appendChild(addrNode)
          vulnerability.appendChild(peerNode)
        
        parameterNode = self.__xmlDoc.createElement("parameter")
        parameterNode.appendChild(self.__xmlDoc.createTextNode(parameter))
        vulnerability.appendChild(parameterNode)

        infoNode = self.__xmlDoc.createElement("info")
        info = info.replace("\n", "<br />")
        infoNode.appendChild(self.__xmlDoc.createTextNode(info))

        vulnerability.appendChild(infoNode)
        self.__addToVulnerabilityList(vulnerabilityTypeName,vulnerability)

    def generateReport(self,fileName):
        """
        Create a xml file with a report of the vulnerabilities which have been logged with 
        the method logVulnerability(vulnerabilityTypeName,level,url,parameter,info)
        """
        f = open(fileName,"w")
        try:
          f.write(self.__xmlDoc.toprettyxml(indent = "    ", encoding = "UTF-8"))
        finally:
          f.close()

if __name__ == "__main__":
    
    SQL_INJECTION = "Sql Injection"
    FILE_HANDLING = "File Handling"
    XSS = "Cross Site Scripting"
    CRLF = "CRLF"
    EXEC = "Commands execution"
    
    try:
        xmlGen = XMLReportGenerator()
        xmlGen.addVulnerabilityType(SQL_INJECTION)
        xmlGen.addVulnerabilityType(FILE_HANDLING)
        xmlGen.addVulnerabilityType(XSS)
        xmlGen.addVulnerabilityType(CRLF)
        xmlGen.addVulnerabilityType(EXEC)
        xmlGen.logVulnerability("SQL Inyection", "1", "url1", "parameter1", "info1")
        xmlGen.logVulnerability("SQL Inyection", "2", "url2", "parameter2", "info2")
        xmlGen.logVulnerability("SQL Inyection", "2", "url3", "parameter3", "info3")
        xmlGen.logVulnerability("SQL Inyection", "3", "url4", "parameter4", "info4")
        xmlGen.logVulnerability("Cross Site Scripting", "3", "url5", "parameter5", "info5")
        xmlGen.logVulnerability("Cross Site Scripting", "3", "url6", "parameter6", "info6")
        xmlGen.logVulnerability("Cross Site Scripting", "2", "url7", "parameter7", "info7")
        xmlGen.logVulnerability("Cross Site Scripting", "1", "url8", "parameter8", "info8")
        xmlGen.logVulnerability("Google Hacking", "2", "url9", "parameter9", "info9")
        xmlGen.printToFile("sampleReport.xml")
    except SystemExit:
        pass


