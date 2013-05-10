#!/usr/bin/env python

# HTML Report Generator Module for Wapiti Project
# Wapiti Project (http://wapiti.sourceforge.net)
#
# Nicolas SURRIBAS
# Alberto Pastor
# David del Pozo
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

import os
from jsonreportgenerator import JSONReportGenerator
from shutil import copytree, rmtree


class HTMLReportGenerator(JSONReportGenerator):
    """
    TODO: change description
    This class generates an XML report calling the method printToFile(fileName) of its Base class (XMLReportGenerator)
    For more information see XMLReportGenerator class
    Also, Copy the report structure in the specified directory
    The structure is as follow:
        /report
        index.html (visualization file)
        vulnerabilities.json (report json file)
        /includes
            /js (contains all js files)
        /css (contains the stylesheet files)
        /images (contains the required images)
    """
    BASE_DIR = os.path.normpath(os.path.join(os.path.abspath(__file__), '../..'))
    REPORT_DIR = "report_template"
    REPORT_JSON_FILE = "vulnerabilities.json"

    def generateReport(self, fileName):
        """
        Copy the report structure in the specified 'fileName' directory
        If these path exists, it will be overwritten
        """
        if os.path.exists(fileName):
            rmtree(fileName)
        copytree(self.BASE_DIR + "/" + self.REPORT_DIR, fileName)

        JSONReportGenerator.generateReport(self, fileName + "/" + self.REPORT_JSON_FILE)
        fd = open(fileName + "/" + self.REPORT_JSON_FILE)
        json_data = fd.read()
        fd.close()

        fd = open(fileName + "/index.html", "r+")
        html_data = fd.read()
        html_data = html_data.replace('__JSON_DATA__', json_data)
        fd.seek(0)
        fd.truncate(0)
        fd.write(html_data)
        fd.close()

if __name__ == "__main__":

    SQL_INJECTION = "Sql Injection"
    FILE_HANDLING = "File Handling"
    XSS = "Cross Site Scripting"
    CRLF = "CRLF"
    EXEC = "Commands execution"
#
#    try:
#        xmlGen = HTMLReportGenerator()
#        xmlGen.addVulnerabilityType(SQL_INJECTION)
#        xmlGen.addVulnerabilityType(FILE_HANDLING)
#        xmlGen.addVulnerabilityType(XSS)
#        xmlGen.addVulnerabilityType(CRLF)
#        xmlGen.addVulnerabilityType(EXEC)
#        xmlGen.logVulnerability("SQL Inyection", "1", "url1", "parameter1", "info1")
#        xmlGen.logVulnerability("SQL Inyection", "2", "url2", "parameter2", "info2")
#        xmlGen.logVulnerability("SQL Inyection", "2", "url3", "parameter3", "info3")
#        xmlGen.logVulnerability("SQL Inyection", "3", "url4", "parameter4", "info4")
#        xmlGen.logVulnerability("Cross Site Scripting", "3", "url5", "parameter5", "info5")
#        xmlGen.logVulnerability("Cross Site Scripting", "3", "url6", "parameter6", "info6")
#        xmlGen.logVulnerability("Cross Site Scripting", "2", "url7", "parameter7", "info7")
#        xmlGen.logVulnerability("Cross Site Scripting", "1", "url8", "parameter8", "info8")
#        xmlGen.logVulnerability("Google Hacking", "2", "url9", "parameter9", "info9")
#        """xmlGen.printToFile("sampleReport.xml")"""
#	xmlGen.generateReport("hola")
#
#    except SystemExit:
#        pass
#
#
