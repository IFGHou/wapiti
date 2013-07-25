#!/usr/bin/env python
# TODO: add err 500 and res consumption check ?
import random
import BeautifulSoup
import requests
from attack import Attack
from vulnerability import Vulnerability
from net import HTTP


class mod_xss(Attack):
    """This class implements a cross site scripting attack"""

    # magic strings we must see to be sure script is vulnerable to XSS
    # payloads must be created on those patterns
    script_ok = ["alert('__XSS__')", "alert(\"__XSS__\")", "String.fromCharCode(0,__XSS__,1)"]

    # simple payloads that doesn't rely on their position in the DOM structure
    # payloads injected after closing a tag attibute value (attrval) or in the
    # content of a tag (text node like beetween <p> and </p>)
    # only trick here must be on character encoding, filter bypassing, stuff like that
    # form the simplest to the most complex, Wapiti will stop on the first working
    independant_payloads = []
    php_self_payload = "%3Cscript%3Ephpselfxss()%3C/script%3E"
    php_self_check = "<script>phpselfxss()</script>"

    name = "xss"

    # two dict exported for permanent XSS scanning
    # GET_XSS structure :
    # {uniq_code : http://url/?param1=value1&param2=uniq_code&param3..., next_uniq_code : ...}
    GET_XSS = {}
    # POST XSS structure :
    # {uniq_code: [target_url, {param1: val1, param2: uniq_code, param3:...}, referer_ul], next_uniq_code : [...]...}
    POST_XSS = {}
    PHP_SELF = []

    # key = xss code, value = payload
    SUCCESSFUL_XSS = {}

    CONFIG_FILE = "xssPayloads.txt"

    MSG_VULN = _("XSS vulnerability")

    def __init__(self, HTTP, xmlRepGenerator):
        Attack.__init__(self, HTTP, xmlRepGenerator)
        self.independant_payloads = self.loadPayloads(self.CONFIG_DIR + "/" + self.CONFIG_FILE)

    def random_string(self):
        """Create a random unique ID that will be used to test injection."""
        """It doesn't upercase letters as BeautifulSoup make some data lowercase."""
        return "w" + "".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0, 9)])

    def _validXSSContentType(self, http_res):
        """Check wether the returned content-type header allow javascript evaluation."""
        # When no content-type is returned, browsers try to display the HTML
        if not "content-type" in http_res.headers:
            return True
        # else only text/html will allow javascript (maybe text/plain will work for IE...)
        if "text/html" in http_res.headers["content-type"]:
            return True
        return False

    def attackGET(self, http_res):
        """This method performs the cross site scripting attack (XSS attack) with method GET"""

        # copies
        page = http_res.path
        params_list = http_res.get_params
        resp_headers = http_res.headers
        referer = http_res.referer
        headers = {}
        if referer:
            headers["referer"] = referer

        # Some PHP scripts doesn't sanitize data coming from $_SERVER['PHP_SELF']
        if page not in self.PHP_SELF:
            evil_req = None
            if page.endswith("/"):
                evil_req = HTTP.HTTPResource(page + self.php_self_payload)
            elif page.endswith(".php"):
                evil_req = HTTP.HTTPResource(page + "/" + self.php_self_payload)
            if evil_req is not None:
                if self.verbose == 2:
                    print(u"+ {0}".format(evil_req.url))
                data, http_code = self.HTTP.send(evil_req, headers=headers).getPageCode()
                if self._validXSSContentType(evil_req) and self.php_self_check in data:
                    self.logR(Vulnerability.MSG_PATH_INJECT, self.MSG_VULN, page)
                    self.logR(Vulnerability.MSG_EVIL_URL, evil_req.url)

                    self.logVuln(category=Vulnerability.XSS,
                                 level=Vulnerability.HIGH_LEVEL,
                                 request=evil_req,
                                 parameter="PHP_SELF",
                                 info=_("XSS vulnerability found via injection in the resource path"))
            self.PHP_SELF.append(page)

        # page is the url of the script
        # params_list is a list of [key, value] lists
        if not params_list:
            # Do not attack application-type files
            if not "content-type" in resp_headers:
                # Sometimes there's no content-type... so we rely on the document extension
                if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
                    return
            elif not "text" in resp_headers["content-type"]:
                return

            url = page + "?__XSS__"
            if url not in self.attackedGET:
                self.attackedGET.append(url)
                code = self.random_string()
                test_req = HTTP.HTTPResource(page + "?" + code)
                self.GET_XSS[code] = (test_req, "QUERY_STRING")
                try:
                    resp = self.HTTP.send(test_req, headers=headers)
                    data = resp.getPage()
                except requests.exceptions.Timeout:
                    data = ""
                    resp = None
                if code in data:
                    payloads = self.generate_payloads(data, code)
                    for payload in payloads:
                        evil_req = HTTP.HTTPResource(page + "?" + self.HTTP.quote(payload))
                        if self.verbose == 2:
                            print(u"+ {0}".format(evil_req))
                        try:
                            resp = self.HTTP.send(evil_req, headers=headers)
                            dat = resp.getPage()
                        except requests.exceptions.Timeout, timeout:
                            dat = ""
                            resp = timeout
                        param_name = "QUERY_STRING"

                        if self._validXSSContentType(evil_req) and dat is not None and len(dat) > 1:
                            if payload.lower() in dat.lower():
                                self.SUCCESSFUL_XSS[code] = payload
                                self.logVuln(category=Vulnerability.XSS,
                                             level=Vulnerability.HIGH_LEVEL,
                                             request=evil_req,
                                             parameter=param_name,
                                             info=_("XSS vulnerability found via injection in the query string"))

                                self.logR(Vulnerability.MSG_QS_INJECT, self.MSG_VULN, page)
                                self.logR(Vulnerability.MSG_EVIL_URL, evil_req.url)
                                # No more payload injection
                                break

        # URL contains parameters
        else:
            for i in xrange(len(params_list)):
                saved_value = params_list[i][1]
                if saved_value is None:
                    saved_value = ""
                param_name = self.HTTP.quote(params_list[i][0])
                params_list[i][1] = "__XSS__"
                url = page + "?" + self.HTTP.encode(params_list)

                if url not in self.attackedGET:
                    self.attackedGET.append(url)
                    code = self.random_string()
                    params_list[i][1] = code
                    test_req = HTTP.HTTPResource(page + "?" + self.HTTP.encode(params_list))
                    self.GET_XSS[code] = (test_req, param_name)
                    try:
                        resp = self.HTTP.send(test_req, headers=headers)
                        data = resp.getPage()
                    except requests.exceptions.Timeout, timeout:
                        data = ""
                        resp = timeout
                    # is the random code on the webpage ?
                    if code in data:
                        # YES! But where exactly ?
                        payloads = self.generate_payloads(data, code)
                        for payload in payloads:

                            params_list[i][1] = payload

                            evil_req = HTTP.HTTPResource(page + "?" + self.HTTP.encode(params_list))
                            if self.verbose == 2:
                                print(u"+ {0}".format(evil_req))
                            try:
                                resp = self.HTTP.send(evil_req, headers=headers)
                                dat = resp.getPage()
                            except requests.exceptions.Timeout, timeout:
                                dat = ""
                                resp = timeout

                            if self._validXSSContentType(evil_req) and dat is not None and len(dat) > 1:
                                if payload.lower() in dat.lower():
                                    self.SUCCESSFUL_XSS[code] = payload
                                    self.logVuln(category=Vulnerability.XSS,
                                                 level=Vulnerability.HIGH_LEVEL,
                                                 request=evil_req,
                                                 parameter=param_name,
                                                 info=_("XSS vulnerability found via injection"
                                                        " in the parameter {0}").format(param_name))

                                    self.logR(Vulnerability.MSG_PARAM_INJECT,
                                              self.MSG_VULN,
                                              page,
                                              param_name)

                                    self.logR(Vulnerability.MSG_EVIL_URL, evil_req.url)
                                    # stop trying payloads and jum to the next parameter
                                    break
                # Restore the value of this argument before testing the next one
                params_list[i][1] = saved_value

    def attackPOST(self, form):
        """This method performs the cross site scripting attack (XSS attack) with method POST"""
        page = form.url
        referer = form.referer
        headers = {}
        if referer:
            headers["referer"] = referer

        if page not in self.PHP_SELF:
            evil_req = None
            if page.endswith("/"):
                evil_req = HTTP.HTTPResource(page + self.php_self_payload)
            elif page.endswith(".php"):
                evil_req = HTTP.HTTPResource(page + "/" + self.php_self_payload)
            if evil_req:
                if self.verbose == 2:
                    print(u"+ {0}".format(evil_req.url))
                data, http_code = self.HTTP.send(evil_req, headers=headers).getPageCode()
                if self._validXSSContentType(evil_req) and self.php_self_check in data:
                    self.logR(Vulnerability.MSG_PATH_INJECT, self.MSG_VULN, page)
                    self.logR(Vulnerability.MSG_EVIL_URL, evil_req.url)

                    self.logVuln(category=Vulnerability.XSS,
                                 level=Vulnerability.HIGH_LEVEL,
                                 request=evil_req,
                                 parameter="PHP_SELF",
                                 info=_("XSS vulnerability found via injection in the resource path"))
            self.PHP_SELF.append(page)

        # copies
        get_params = form.get_params
        post_params = form.post_params
        file_params = form.file_params

        for params_list in [get_params, post_params, file_params]:
            for i in xrange(len(params_list)):
                param_name = self.HTTP.quote(params_list[i][0])
                saved_value = params_list[i][1]
                if saved_value is None:
                    saved_value = ""
                if params_list is file_params:
                    params_list[i][1] = ["_XSS__", params_list[i][1][1]]
                else:
                    params_list[i][1] = "__XSS__"
                # We keep an attack pattern to be sure a given form won't be attacked on the same field several times
                attack_pattern = HTTP.HTTPResource(form.path,
                                                   method=form.method,
                                                   get_params=get_params,
                                                   post_params=post_params,
                                                   file_params=file_params)
                if not attack_pattern in self.attackedPOST:
                    self.attackedPOST.append(attack_pattern)
                    code = self.random_string()
                    if params_list is file_params:
                        params_list[i][1][0] = code
                    else:
                        params_list[i][1] = code
                    # will only memorize the last used payload (working or not) but the code will always be the good
                    test_payload = HTTP.HTTPResource(form.path,
                                                     method=form.method,
                                                     get_params=get_params,
                                                     post_params=post_params,
                                                     file_params=file_params,
                                                     referer=referer)

                    self.POST_XSS[code] = (test_payload, param_name)
                    try:
                        resp = self.HTTP.send(test_payload)
                        data = resp.getPage()
                    except requests.exceptions.Timeout, timeout:
                        data = ""
                        resp = timeout
                    # rapid search on the code to check injection
                    if code in data:
                        # found, now study where the payload is injected and how to exploit it
                        payloads = self.generate_payloads(data, code)
                        for payload in payloads:
                            if params_list is file_params:
                                params_list[i][1][0] = payload
                            else:
                                params_list[i][1] = payload

                            evil_req = HTTP.HTTPResource(form.path,
                                                         method=form.method,
                                                         get_params=get_params,
                                                         post_params=post_params,
                                                         file_params=file_params,
                                                         referer=referer)

                            if self.verbose == 2:
                                print(u"+ {0}".format(evil_req))
                            try:
                                resp = self.HTTP.send(evil_req)
                                dat = resp.getPage()
                            except requests.exceptions.Timeout, timeout:
                                dat = ""
                                resp = timeout

                            if self._validXSSContentType(evil_req) and dat is not None and len(dat) > 1:
                                if payload.lower() in dat.lower():
                                    self.SUCCESSFUL_XSS[code] = payload
                                    self.logVuln(category=Vulnerability.XSS,
                                                 level=Vulnerability.HIGH_LEVEL,
                                                 request=evil_req,
                                                 parameter=param_name,
                                                 info=_("XSS vulnerability found via injection"
                                                        " in the parameter {0}").format(param_name))

                                    self.logR(Vulnerability.MSG_PARAM_INJECT,
                                              self.MSG_VULN,
                                              evil_req.url,
                                              param_name)

                                    self.logR(Vulnerability.MSG_EVIL_REQUEST)
                                    self.logC(evil_req.http_repr)
                                    print('')
                                    # Stop injecting payloads and move to the next parameter
                                    break

                # restore the saved parameter in the list
                params_list[i][1] = saved_value

    def closeNoscript(self, tag):
        """Return a string with each closing parent tags for escaping a noscript"""
        s = ""
        if tag.findParent("noscript"):
            curr = tag.parent
            while True:
                s += "</{0}>".format(curr.name)
                if curr.name == "noscript":
                    break
                curr = curr.parent
        return s

    # type/name/tag ex: attrval/img/src
    # TODO: entries is a mutable argument, check this
    def study(self, obj, parent=None, keyword="", entries=[]):
        #if parent==None:
        #  print("Keyword is: {0}".format(keyword))
        if keyword in str(obj):
            if isinstance(obj, BeautifulSoup.Tag):
                if keyword in str(obj.attrs):
                    for k, v in obj.attrs:
                        if keyword in v:
                            # print("Found in attribute value {0} of tag {1}".format(k, obj.name))
                            noscript = self.closeNoscript(obj)
                            entries.append({"type": "attrval", "name": k, "tag": obj.name, "noscript": noscript})
                        if keyword in k:
                            # print("Found in attribute name {0} of tag {1}".format(k, obj.name))
                            noscript = self.closeNoscript(obj)
                            entries.append({"type": "attrname", "name": k, "tag": obj.name, "noscript": noscript})
                elif keyword in obj.name:
                    # print("Found in tag name")
                    noscript = self.closeNoscript(obj)
                    entries.append({"type": "tag", "value": obj.name, "noscript": noscript})
                else:
                    for x in obj.contents:
                        # recursive search
                        self.study(x, obj, keyword, entries)
            elif isinstance(obj, BeautifulSoup.NavigableString):
                if keyword in str(obj):
                    # print("Found in text, tag {0}".format(parent.name))
                    noscript = self.closeNoscript(obj)
                    entries.append({"type": "text", "parent": parent.name, "noscript": noscript})

    # generate a list of payloads based on where in the webpage the js-code will be injected
    def generate_payloads(self, data, code):
        soup = BeautifulSoup.BeautifulSoup(data)  # il faut garder la page non-retouchee en reserve...
        e = []
        self.study(soup, keyword=code, entries=e)

        payloads = []

        for elem in e:
            payload = ""
            # Try each case where our string can be found
            # Leave at the first possible exploitation found

            # Our string is in the value of a tag attribute
            # ex: <a href="our_string"></a>
            if elem['type'] == "attrval":
                # print("tag -> {0}".format(elem['tag']))
                # print(elem['name'])
                i0 = data.find(code)
                # i1=data[:i0].rfind("=")
                try:
                    # find the position of name of the attribute we are in
                    i1 = data[:i0].rfind(elem['name'])
                # stupid unicode errors, must check later
                except UnicodeDecodeError:
                    continue

                start = data[i1:i0].replace(" ", "")[len(elem['name']):]
                # between the tag name and our injected attribute there is an equal sign
                # and (probably) a quote or a double-quote we need to close before putting our payload
                if start.startswith("='"):
                    payload = "'"
                if start.startswith('="'):
                    payload = '"'
                if elem['tag'].lower() == "img":
                    payload += "/>"
                else:
                    payload += "></" + elem['tag'] + ">"

                payload += elem['noscript']
                # ok let's send the requests
                for xss in self.independant_payloads:
                    payloads.append(payload + xss.replace("__XSS__", code))

            # we control an attribute name
            # ex: <a our_string="/index.html">
            elif elem['type'] == "attrname":  # name,tag
                if code == elem['name']:
                    for xss in self.independant_payloads:
                        payloads.append('>' + elem['noscript'] + xss.replace("__XSS__", code))

            # we control the tag name
            # ex: <our_string name="column" />
            elif elem['type'] == "tag":
                if elem['value'].startswith(code):
                    # use independant payloads, just remove the first character (<)
                    for xss in self.independant_payloads:
                        payload = elem['noscript'] + xss.replace("__XSS__", code)
                        payloads.append(payload[1:])
                else:
                    for xss in self.independant_payloads:
                        payload = "/>" + elem['noscript'] + xss.replace("__XSS__", code)
                        payloads.append(payload)

            # we control the text of the tag
            # ex: <textarea>our_string</textarea>
            elif elem['type'] == "text":
                if elem['parent'] in ["title", "textarea"]:  # we can't execute javascript in those tags
                    if elem['noscript'] != "":
                        payload = elem['noscript']
                    else:
                        payload = "</{0}>".format(elem['parent'])
                elif elem['parent'] == "script":  # Control over the body of a script :)
                    # Just check if we can use brackets
                    payloads.insert(0, "String.fromCharCode(0,__XSS__,1)".replace("__XSS__", code))

                for xss in self.independant_payloads:
                    payloads.append(payload + xss.replace("__XSS__", code))

            data = data.replace(code, "none", 1)  # reduire la zone de recherche
        return payloads
