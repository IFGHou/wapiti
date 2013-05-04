#!/usr/bin/env python
# Wapiti SVN - A web application vulnerability scanner
# Wapiti Project (http://wapiti.sourceforge.net)
# Copyright (C) 2008 Nicolas Surribas
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
import BeautifulSoup
from attack import Attack
from vulnerability import Vulnerability
from vulnerabilitiesdescriptions import VulnerabilitiesDescriptions as VulDescrip
import csv
import re
import os
import socket

# Nikto databases are csv files with the following fields (in order) :
#
# 1 - A unique indenfier (number)
# 2 - The OSVDB reference number of the vulnerability
# 3 - Unknown (not used by Wapiti)
# 4 - The URL to check for. May contain a pattern to replace (eg: @CGIDIRS)
# 5 - The HTTP method to use when requesting the URL
# 6 - The HTTP status code returned when the vulnerability may exist
#     or a string the HTTP response may contain.
# 7 - Another condition for a possible vulnerability (6 OR 7)
# 8 - Another condition (must match for a possible vulnerability)
# 9 - A condition corresponding to an unexploitable webpage
#10 - Another condition just like 9
#11 - A description of the vulnerability with possible BID, CVE or MS references
#12 - A url-form-encoded string (usually for POST requests)
#
# A possible vulnerability is reported in the following condition :
# ((6 or 7) and 8) and not (9 or 10)


class mod_nikto(Attack):
    """
    This class implements a Nikto attack
    """

    nikto_db = []

    name = "nikto"
    CONFIG_FILE = "nikto_db"

    doGET = False
    doPOST = False

    def __init__(self, HTTP, xmlRepGenerator):
        Attack.__init__(self, HTTP, xmlRepGenerator)
        user_config_dir = os.getenv('HOME') or os.getenv('USERPROFILE')
        user_config_dir += "/config"
        if not os.path.isdir(user_config_dir):
            os.makedirs(user_config_dir)
        try:
            fd = open(user_config_dir + "/" + self.CONFIG_FILE)
            reader = csv.reader(fd)
            self.nikto_db = [l for l in reader if l != [] and l[0].isdigit()]
            fd.close()
        except IOError:
            try:
                print _("Problem with local nikto database.")
                print _("Downloading from the web...")
                resp = self.HTTP.send("http://cirt.net/nikto/UPDATES/2.1.5/db_tests")
                page = resp.getRawPage()

                csv.register_dialect("nikto", quoting=csv.QUOTE_ALL, doublequote=False, escapechar="\\")
                reader = csv.reader(page.split("\n"), "nikto")
                self.nikto_db = [l for l in reader if l != [] and l[0].isdigit()]

                fd = open(user_config_dir + "/" + self.CONFIG_FILE, "w")
                writer = csv.writer(fd)
                writer.writerows(self.nikto_db)
                fd.close()
            except socket.timeout:
                print _("Error downloading Nikto database")

    def attack(self, urls, forms):
        for l in self.nikto_db:
            match = match_or = match_and = False
            fail = fail_or = False

            l[3] = l[3].replace("@CGIDIRS", "/cgi-bin/")
            l[3] = l[3].replace("@ADMIN", "/admin/")
            l[3] = l[3].replace("@NUKE", "/modules/")
            l[3] = l[3].replace("@PHPMYADMIN", "/phpMyAdmin/")
            l[3] = l[3].replace("@POSTNUKE", "/postnuke/")
            if l[3][0] == "@":
                continue
            if l[3][0] != "/":
                l[3] = "/" + l[3]

            url = ""
            try:
                url = "http://" + self.HTTP.server + l[3]
            except UnicodeDecodeError:
                continue

            if l[4] == "GET":
                resp = self.HTTP.send(url)
            elif l[4] == "POST":
                resp = self.HTTP.send(url, post_params=l[11])
            else:
                resp = self.HTTP.send(url, post_params=l[11], method=l[4])

            page, code = resp.getPageCode()
            encoding = BeautifulSoup.BeautifulSoup(page).originalEncoding
            if encoding:
                page = unicode(page, encoding, "ignore")
            raw = " ".join([x + ": " + y for x, y in resp.getHeaders().items()])
            raw += page

            # First condition (match)
            if len(l[5]) == 3 and l[5].isdigit():
                if code == int(l[5]):
                    match = True
            else:
                if l[5] in raw:
                    match = True

            # Second condition (or)
            if l[6] != "":
                if len(l[6]) == 3 and l[6].isdigit():
                    if code == int(l[6]):
                        match_or = True
                else:
                    if l[6] in raw:
                        match_or = True

            # Third condition (and)
            if l[7] != "":
                if len(l[7]) == 3 and l[7].isdigit():
                    if code == int(l[7]):
                        match_and = True
                else:
                    if l[7] in raw:
                        match_and = True
            else:
                match_and = True

            # Fourth condition (fail)
            if l[8] != "":
                if len(l[8]) == 3 and l[8].isdigit():
                    if code == int(l[8]):
                        fail = True
                else:
                    if l[8] in raw:
                        fail = True

            # Fifth condition (or)
            if l[9] != "":
                if len(l[9]) == 3 and l[9].isdigit():
                    if code == int(l[9]):
                        fail_or = True
                else:
                    if l[9] in raw:
                        fail_or = True

            if ((match or match_or) and match_and) and not (fail or fail_or):
                print url
                print l[10]
                refs = []
                if l[1] != "0":
                    refs.append("http://osvdb.org/show/osvdb/" + l[1])

                # CERT
                m = re.search("(CA\-[0-9]{4}-[0-9]{2})", l[10])
                if m is not None:
                    refs.append("http://www.cert.org/advisories/" + m.group(0) + ".html")

                # SecurityFocus
                m = re.search("BID\-([0-9]{4})", l[10])
                if m is not None:
                    refs.append("http://www.securityfocus.com/bid/" + m.group(1))

                # Mitre.org
                m = re.search("((CVE|CAN)\-[0-9]{4}-[0-9]{4})", l[10])
                if m is not None:
                    refs.append("http://cve.mitre.org/cgi-bin/cvename.cgi?name=" + m.group(0))

                # CERT Incidents
                m = re.search("(IN\-[0-9]{4}\-[0-9]{2})", l[10])
                if m is not None:
                    refs.append("http://www.cert.org/incident_notes/" + m.group(0) + ".html")

                # Microsoft Technet
                m = re.search("(MS[0-9]{2}\-[0-9]{3})", l[10])
                if m is not None:
                    refs.append("http://www.microsoft.com/technet/security/bulletin/" + m.group(0) + ".asp")

                info = l[10]
                if refs != []:
                    print _("References:") + "\n  " + "\n  ".join(refs)
                    info += "\n" + _("References:") + "\n"
                    info += "\n".join(['<a href="' + x + '">' + x + '</a>' for x in refs])
                print

                if l[4] == "GET":
                    self.logVuln(category=Vulnerability.NIKTO,
                                 level=Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                 request=url,
                                 info=info)
                elif l[4] == "POST":
                    self.logVuln(category=Vulnerability.NIKTO,
                                 level=Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                 request=url,  # l[11],
                                 info=info)
                else:
                    self.logVuln(category=Vulnerability.NIKTO,
                                 level=Vulnerability.HIGH_LEVEL_VULNERABILITY,
                                 request=url,  # l[4] + " " + l[11],
                                 info=info)
