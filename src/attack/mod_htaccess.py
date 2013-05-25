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
#
# Authors:
# Anthony DUBOCAGE
# Guillaume TRANCHANT
# Gregory FONTAINE
# Nicolas SURRIBAS

from attack import Attack
from vulnerability import Vulnerability, Anomaly
from net import HTTP


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
        code = int(code)
        if code == 401:
            err = "Authorization Required"
        elif code == 402:
            err = "Payment Required"
        elif code == 403:
            err = "Forbidden"
        else:
            err = "ok"
        return err

    def attackGET(self, http_res):
        page = http_res.path
        resp_headers = http_res.headers
        referer = http_res.referer
        headers = {}
        if referer:
            headers["referer"] = referer

        url = page
        if url not in self.attackedGET:
            if self.verbose == 2:
                print(u"+ {0}".format(url))

            err1 = self.__returnErrorByCode(resp_headers["status_code"])

            if err1 != "ok":
                data1 = self.HTTP.send(url, headers=headers).getPage()
                # .htaccess protection detected
                if self.verbose >= 1:
                    print(_("HtAccess protection found: {0}").format(url))

                evil_req = HTTP.HTTPResource(url, method="ABC")
                data2, code2 = self.HTTP.send(evil_req, headers=headers).getPageCode()
                err2 = self.__returnErrorByCode(code2)

                if err2 == "ok":
                    # .htaccess bypass success

                    if self.verbose >= 1:
                        if self.color == 1:
                            print(_("{0}|HTTP Code: {1} : {2}{3}")
                                  .format(self.CYAN, resp_headers["status_code"], err1, self.STD))
                        else:
                            print(_("|HTTP Code: {0} : {1}").format(resp_headers["status_code"], err1))

                    if self.verbose == 2:
                        if self.color == 1:
                            print(_("{0}Source code:{1}").format(self.YELLOW, self.STD))
                            print(u"{0}{1}{2}".format(self.GB, data1, self.STD))
                        else:
                            print(_("Source code:"))
                            print(data1)

                    # report xml generator (ROMULUS) not implemented for htaccess
                    self.logVuln(category=Vulnerability.HTACCESS,
                                 level=Vulnerability.HIGH_LEVEL,
                                 request=evil_req,
                                 info=_("{0} HtAccess").format(err1))
                    if self.color == 1:
                        print(_("{0}  .htaccess bypass vulnerability: {1}{2}")
                              .format(self.RED, evil_req.url, self.STD))
                    else:
                        print(_("  .htaccess bypass vulnerability: {0}").format(evil_req.url))

                    # print output informations by verbosity option
                    if self.verbose >= 1:
                        if self.color == 1:
                            print(_("{0}|HTTP Code: {1}{2}").format(self.CYAN, code2, self.STD))
                        else:
                            print(_("|HTTP Code: {0}").format(code2))

                    if self.verbose == 2:
                        if self.color == 1:
                            print(_("{0}Source code:{1}").format(self.YELLOW, self.STD))
                            print(u"{0}{1}{2}".format(self.GB, data2, self.STD))
                        else:
                            print(_("Source code:"))
                            print(data2)

                else:
                    # TODO : still need this ?
                    if code2 == 500:
                        self.logAnom(category=Anomaly.ERROR_500,
                                     level=Anomaly.HIGH_LEVEL,
                                     request=evil_req,
                                     info=_("The server responded with a 500 HTTP error code"))
                        self.log(Anomaly.MSG_500, page)
                        self.log(Anomaly.MSG_EVIL_URL, url)

                    # add the url with the url attacked
                self.attackedGET.append(url)
