#!/usr/bin/env python
#
# Authors:
# Anthony DUBOCAGE
# Guillaume TRANCHANT
# Gregory FONTAINE
# Nicolas SURRIBAS

from attack import Attack
from vulnerability import Vulnerability
import socket
from net import HTTP


class mod_backup(Attack):
    """
    This class implements a "backup attack"
    """

    payloads = []
    CONFIG_FILE = "backupPayloads.txt"

    name = "backup"

    doGET = False
    doPOST = False

    def __init__(self, HTTP, xmlRepGenerator):
        Attack.__init__(self, HTTP, xmlRepGenerator)
        self.payloads = self.loadPayloads(self.CONFIG_DIR + "/" + self.CONFIG_FILE)

    def __returnErrorByCode(self, code):
        err = ""
        if code == 404:
            err = "Not found"

        if 100 <= code < 300:
            err = "ok"

        return err

    def attackGET(self, http_res):
        page = http_res.path
        headers = http_res.headers

        # Do not attack application-type files
        if not "content-type" in headers:
            # Sometimes there's no content-type... so we rely on the document extension
            if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
                return
        elif not "text" in headers["content-type"]:
            return

        for ext in self.payloads:
            url = page + ext

            if self.verbose == 2:
                print(u"+ {0}".format(url))

            if url not in self.attackedGET:
                self.attackedGET.append(url)
                try:
                    evil_req = HTTP.HTTPResource(url)

                    resp = self.HTTP.send(evil_req)
                    data, code = resp.getPageCode()
                    err = self.__returnErrorByCode(code)
                    if err == "ok":
                        if self.color == 1:
                            print(_("{0}Found backup file !{1}").format(self.RED, self.STD))
                            print(u"{0}    -> {1}{2}".format(self.RED, evil_req.url, self.STD))
                        else:
                            print(_(" + Found backup file !"))
                            print(u"   -> {0}".format(evil_req.url))
                        self.logVuln(category=Vulnerability.BACKUP,
                                     level=Vulnerability.HIGH_LEVEL,
                                     request=evil_req,
                                     info=_("Backup file {0} found for {1}").format(url, page))

                except socket.timeout:
                    break
