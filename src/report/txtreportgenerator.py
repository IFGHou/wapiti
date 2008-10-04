#!/usr/bin/env python

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

from reportgenerator import ReportGenerator

class TXTReportGenerator(ReportGenerator):
    """
    This class generates a report with the method printToFile(fileName) which contains
    the information of all the vulnerabilities notified to this object through the 
    method logVulnerability(vulnerabilityTypeName,level,url,parameter,info).
    The format of the file is XML and it has the following structure:
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

    SQL_INJECTION = "SQL Injection"
    FILE_HANDLING = "File Handling"
    XSS = "Cross Site Scripting"
    CRLF = "CRLF"
    EXEC = "Commands execution"

    __sqlVulns=[]
    __fileVulns=[]
    __xssVulns=[]
    __crlfVulns=[]
    __execVulns=[]

    __vulnTypes={}

    def __init__(self):
      pass

    def addVulnerabilityType(self,name,description="",solution="",references={}):
        """
        This method adds a vulnerability type, it can be invoked to include in the
        report the type. 
        The types are not stored previously, they are added when the method 
        logVulnerability(vulnerabilityTypeName,level,url,parameter,info) is invoked
        and if there is no vulnerabilty of a type, this type will not be presented
        in the report
        """

        if name not in self.__vulnTypes.keys():
          self.__vulnTypes[name]={'desc':description,'sol':solution,'ref':references}
          #ref : title / url

    def __addToVulnerabilityList(self,vulnerabilityTypeName,vulnerability):
        vulnerabilityType = None
        for node in self.__vulnerabilityTypeList.childNodes:
            if node.nodeType == node.ELEMENT_NODE and node.getAttribute("name") == vulnerabilityTypeName:
                vulnerabilityType = node
                break
        if vulnerabilityType == None:
            vulnerabilityType = self.addVulnerabilityType(vulnerabilityTypeName)
        vulnerabilityType.childNodes[0].appendChild(vulnerability)

    def logVulnerability(self,vulnerabilityTypeName,level,url,parameter,info):
        """
        Store the information about the vulnerability to be printed later.
        The method printToFile(fileName) can be used to save in a file the
        vulnerabilities notified through the current method.
        """

        if vulnerabilityTypeName==self.SQL_INJECTION:
          self.__sqlVulns.append([level,url,parameter,info])
        elif vulnerabilityTypeName==self.FILE_HANDLING: 
          self.__fileVulns.append([level,url,parameter,info])
        elif vulnerabilityTypeName==self.XSS:
          self.__xssVulns.append([level,url,parameter,info])
        elif vulnerabilityTypeName==self.CRLF:
          self.__crlfVulns.append([level,url,parameter,info])
        elif vulnerabilityTypeName==self.EXEC:
          self.__execVulns.append([level,url,parameter,info])

    def generateReport(self,fileName):
        """
        Create a xml file with a report of the vulnerabilities which have been logged with 
        the method logVulnerability(vulnerabilityTypeName,level,url,parameter,info)
        """
        f = open(fileName,"w")
        try:
            f.write("Vulnerabilities report -- Wapiti\n")
            f.write("  http://wapiti.sourceforge.net\n\n")
            for name in self.__vulnTypes.keys():
                if name==self.SQL_INJECTION and self.__sqlVulns!=[]:
                    f.write("SQL Injections vulnerabilities:\n")
                    for vuln in self.__sqlVulns:
                        f.write("    in url "+vuln[1]+"\n")
                        f.write("    with parameters "+vuln[2]+"\n")
                        f.write("\n")
                elif name==self.FILE_HANDLING and self.__fileVulns!=[]:
                    f.write("File Handling vulnerabilities:\n")
                    for vuln in self.__fileVulns:
                        f.write("    in url "+vuln[1]+"\n")
                        f.write("    with parameters "+vuln[2]+"\n")
                        f.write("\n")
                elif name==self.XSS and self.__xssVulns!=[]:
                    f.write("Cross Site Scripting vulnerabilities:\n")
                    for vuln in self.__xssVulns:
                        f.write("    in url "+vuln[1]+"\n")
                        f.write("    with parameters "+vuln[2]+"\n")
                        f.write("\n")
                elif name==self.CRLF and self.__crlfVulns!=[]:
                    f.write("CRLF Injection vulnerabilities:\n")
                    for vuln in self.__crlfVulns:
                        f.write("    in url "+vuln[1]+"\n")
                        f.write("    with parameters "+vuln[2]+"\n")
                        f.write("\n")
                elif name==self.EXEC and self.__execVulns!=[]:
                    f.write("Command Execution vulnerabilities:\n")
                    for vuln in self.__execVulns:
                        f.write("    in url "+vuln[1]+"\n")
                        f.write("    with parameters "+vuln[2]+"\n")
                        f.write("\n")
            f.write("This report has been generated by Wapiti Web Application Scanner\n")
        finally:
            f.close()

