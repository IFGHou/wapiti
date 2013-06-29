#!/usr/bin/env python

# JSON Report Generator Module for Wapiti Project
# Wapiti Project (http://wapiti.sourceforge.net)
#
# Copyright (C) 2013 Nicolas SURRIBAS
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
import json


class JSONReportGenerator(ReportGenerator):
    """
    TODO: MUST BE CHANGED
    """

    # Use only one dict for vulnerability and anomaly types
    __flawTypes = {}

    __vulns = {}
    __anomalies = {}

    __infos = {}

    def __init__(self):
        pass

    def setReportInfo(self, target, scope=None, date_string="", version=""):
        self.__infos["target"] = target
        self.__infos["date"] = date_string
        self.__infos["version"] = version
        if scope:
            self.__infos["scope"] = scope

    def generateReport(self, fileName):
        """
        Create a json file with a report of the vulnerabilities which have
        been logged with the logVulnerability method
        """
        report_dict = {"classifications": self.__flawTypes,
                       "vulnerabilities": self.__vulns,
                       "anomalies": self.__anomalies,
                       "infos": self.__infos
                       }
        #TODO: add info on wapiti ?
        f = open(fileName, "w")
        try:
            json.dump(report_dict, f, indent=2)
        finally:
            f.close()

    # Vulnerabilities
    def addVulnerabilityType(self, name,
                             description="",
                             solution="",
                             references={}):
        if name not in self.__flawTypes:
            self.__flawTypes[name] = {'desc': description,
                                      'sol': solution,
                                      'ref': references}
        if name not in self.__vulns:
            self.__vulns[name] = []

    def logVulnerability(self,
                         category=None,
                         level=0,
                         request=None,
                         parameter="",
                         info=""):
        """
        Store the information about the vulnerability to be printed later.
        The method printToFile(fileName) can be used to save in a file the
        vulnerabilities notified through the current method.
        """

        vuln_dict = {"method": request.method,
                     "path": request.file_path,  # TODO: path or file_path according to the scope ?
                     "info": info,
                     "level": level,
                     "parameter": parameter,
                     "http_request": request.http_repr,
                     "curl_command": request.curl_repr,
                     }
        if category not in self.__vulns:
            self.__vulns[category] = []
        self.__vulns[category].append(vuln_dict)

    # Anomalies
    def addAnomalyType(self, name,
                       description="",
                       solution="",
                       references={}):
        if name not in self.__flawTypes:
            self.__flawTypes[name] = {'desc': description,
                                      'sol': solution,
                                      'ref': references}
        if name not in self.__anomalies:
            self.__anomalies[name] = []

    def logAnomaly(self,
                   category=None,
                   level=0,
                   request=None,
                   parameter="",
                   info=""):
        """
        Store the information about the vulnerability to be printed later.
        The method printToFile(fileName) can be used to save in a file the
        vulnerabilities notified through the current method.
        """

        anom_dict = {"method": request.method,
                     "path": request.file_path,  # TODO: path or file_path according to the scope ?
                     "info": info,
                     "level": level,
                     "parameter": parameter,
                     "http_request": request.http_repr,
                     "curl_command": request.curl_repr,
                     }
        if category not in self.__anomalies:
            self.__anomalies[category] = []
        self.__anomalies[category].append(anom_dict)
