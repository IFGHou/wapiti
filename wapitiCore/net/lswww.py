#!/usr/bin/env python
# -*- coding: utf-8 -*-
# lswww v2.4.0 - A web spider library
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2006-2013 Nicolas SURRIBAS
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
import re
import socket
import getopt
import os
import HTMLParser
import urllib
import urlparse
import requests
from htmlentitydefs import name2codepoint as n2cp
from xml.dom import minidom
from bs4 import BeautifulSoup

from wapitiCore.net import jsoncookie
from wapitiCore.net import HTTP
from wapitiCore.net import swf_parser
from wapitiCore.net import lamejs
from wapitiCore.net.crawlerpersister import CrawlerPersister


class lswww(object):
    """
    lswww explore a website and extract links and forms fields.

    Usage: python lswww.py http://server.com/base/url/ [options]

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
            Example: -p http://proxy:port/

        -c <cookie_file>
        --cookie <cookie_file>
            To use a cookie

        -a <login%password>
        --auth <login%password>
            Set credentials for HTTP authentication
            Doesn't work with Python 2.4

        -r <parameter_name>
        --remove <parameter_name>
            Remove a parameter from URLs

        -v <level>
        --verbose <level>
            Set verbosity level
            0: only print results
            1: print a dot for each url found (default)
            2: print each url

        -t <timeout>
        --timeout <timeout>
            Set the timeout (in seconds)

        -n <limit>
        --nice <limit>
            Define a limit of urls to read with the same pattern
            Use this option to prevent endless loops
            Must be greater than 0

        -i <file>
        --continue <file>
            This parameter indicates Wapiti to continue with the scan
            from the specified file, this file should contain data
            from a previous scan.
            The file is optional, if it is not specified, Wapiti takes
            the default file from \"scans\" folder.

        -h
        --help
            To print this usage message
    """

    SCOPE_DOMAIN = "domain"
    SCOPE_FOLDER = "folder"
    SCOPE_PAGE = "page"
    SCOPE_DEFAULT = "default"

    allowed = ['php', 'html', 'htm', 'xml', 'xhtml', 'xht', 'xhtm',
               'asp', 'aspx', 'php3', 'php4', 'php5', 'txt', 'shtm',
               'shtml', 'phtm', 'phtml', 'jhtml', 'pl', 'jsp', 'cfm', 'cfml']
    allowed_types = ['text/', 'application/xml']

    def __init__(self, root, http_engine=None):
        self.h = http_engine
        if root.startswith("-"):
            print(_("First argument must be the root url !"))
            sys.exit(0)
        if not "://" in root:
            root = "http://" + root
        if self.__checklink(root):
            print(_("Invalid protocol: {0}").format(root.split("://")[0]))
            sys.exit(0)
        if root[-1] != "/" and not "/" in root.split("://")[1]:
            root += "/"

        self.out_of_scope_urls = []
        self.browsed_links = []
        self.proxies = {}
        self.excluded = []
        self.browsed_forms = []
        self.uploads = []

        self.verbose = 0
        self.auth_basic = []
        self.bad_params = []
        self.timeout = 6.0
        self.global_headers = {}
        self.cookiejar = None
        self.scope = None
        self.link_encoding = {}

        # 0 means no limits
        self.nice = 0
        self.max_link_depth = 40

        server = (root.split("://")[1]).split("/")[0]
        self.root = HTTP.HTTPResource(root)   # Initial URL
        self.server = server  # Domain (with potential :port)
        self.scope_url = root  # Scope of the analysis

        self.tobrowse = [self.root]
        self.persister = CrawlerPersister()

    def setTimeOut(self, timeout=6.0):
        """Set the timeout in seconds to wait for a page"""
        self.timeout = timeout

    def setProxy(self, proxy=""):
        """Set proxy preferences"""
        url_parts = urlparse.urlparse(proxy)
        protocol = url_parts.scheme
        host = url_parts.netloc
        if protocol in ["http", "https"]:
            if host:
                self.proxies[protocol] = "%s://%s/" % (protocol, host)

    def setNice(self, nice=0):
        """Set the maximum of urls to visit with the same pattern"""
        self.nice = nice

    def setMaxLinkDepth(self, maximum):
        """Set how deep the scanner should explore the website"""
        self.max_link_depth = maximum

    def setScope(self, scope):
        self.scope = scope
        if scope == self.SCOPE_FOLDER:
            self.scope_url = "/".join(self.root.url.split("/")[:-1]) + "/"
        elif scope == self.SCOPE_DOMAIN:
            self.scope_url = self.root.url.split("/")[0] + "//" + self.server

    def addStartURL(self, url):
        if self.__checklink(url):
            print(_("Invalid link argument: {0}").format(url))
            sys.exit(0)
        if self.__inzone(url) == 0:
            self.tobrowse.append(HTTP.HTTPResource(url))
        else:
            self.out_of_scope_urls.append(HTTP.HTTPResource(url))

    def addExcludedURL(self, url):
        """Add an url to the list of forbidden urls"""
        self.excluded.append(url)

    def setCookieFile(self, cookie):
        """Set the file to read the cookie from"""
        if os.path.isfile(cookie):
            jc = jsoncookie.jsoncookie()
            jc.open(cookie)
            self.cookiejar = jc.cookiejar(self.server)
            jc.close()

    def setAuthCredentials(self, auth_basic):
        self.auth_basic = auth_basic

    def addBadParam(self, bad_param):
        self.bad_params.append(bad_param)

    def browse(self, web_resource):
        """Extract urls from a webpage and add them to the list of urls
        to browse if they aren't in the exclusion list"""

        # We are going too much deep, don't browse this link
        if web_resource.link_depth > self.max_link_depth:
            return False

        url = web_resource.url

        # We don't need destination anchors
        current_full_url = url.split("#")[0]
        # Url without query string
        current = current_full_url.split("?")[0]
        # Get the dirname of the file
        currentdir = "/".join(current.split("/")[:-1]) + "/"

        # Timeout must not be too long to block big documents
        # (for example a download script)
        # and not too short to give good results
        socket.setdefaulttimeout(self.timeout)

        headers = {"user-agent": 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}
        try:
            resp = self.h.send(web_resource, headers=headers)
        except socket.timeout:
            self.excluded.append(url)
            return False
        except requests.exceptions.Timeout:
            self.excluded.append(url)
            return False
        except socket.error, msg:
            if msg.errno == 111:
                print(_("Connection refused!"))
            self.excluded.append(url)
            return False
        except Exception, e:
            print(_("Exception in lswww.browse: {0}").format(e))
            self.excluded.append(url)
            return False

        if resp is None:
            return False

        info = resp.getHeaders()
        code = resp.getCode()
        info["status_code"] = code

        if not url in self.link_encoding:
            self.link_encoding[url] = ""

        proto = url.split("://")[0]
        if proto == "http" or proto == "https":
            if not isinstance(proto, unicode):
                proto = unicode(proto)
            # Check the content-type first
            # if not info.has_key("content-type"):
                # Sometimes there's no content-type...
                #so we rely on the document extension
            # if (current.split(".")[-1] not in self.allowed)
            #    and current[-1] != "/":
            #    return info
            # elif info["content-type"].find("text") == -1:
            #   return info

        # No files more than 2MB
        if "content-length" in info:
            if int(info["content-length"]) > 2097152:
                return False

        page_encoding = None
        resp_encoding = resp.getEncoding()
        content_type = resp.getHeaders().get('content-type', '')
        mime_type = content_type.split(';')[0].strip()
        swf_links = []
        js_links = []
        current_depth = web_resource.link_depth

        # Requests says it found an encoding... the content must be some HTML
        if resp_encoding and any(mime_type.startswith(t) for t in self.allowed_types):
            # use charade (included in requests) to detect the real encoding
            page_encoding = resp.getApparentEncoding()
            if page_encoding:
                if page_encoding != resp_encoding:
                    # Mismatch ! Convert the response text to the encoding detected by BeautifulSoup
                    resp.setEncoding(page_encoding)
            else:
                page_encoding = resp_encoding
            data = resp.getPage()
        else:
            # Can't find an encoding... beware of non-html content
            data = resp.getRawPage()
            if "application/x-shockwave-flash" in mime_type or web_resource.file_ext == "swf":
                try:
                    flash_parser = swf_parser.swf_parser(data)
                    swf_links = flash_parser.getLinks()
                except Exception, err_data:
                    swf_links = err_data[1]
            elif "/x-javascript" in mime_type or "/x-js" in mime_type or "/javascript" in mime_type:
                js_links = lamejs.lamejs(data).getLinks()
            data = ""

        # Manage redirections
        if "location" in info:
            redir = self.correctlink(info["location"], current, current_full_url, currentdir, proto, None)
            if redir is not None:
                if self.__inzone(redir) == 0:
                    self.link_encoding[redir] = self.link_encoding[url]
                    redir = HTTP.HTTPResource(redir, link_depth=current_depth+1)
                    # Is the document not visited yet and not forbidden ?
                    if (redir not in self.browsed_links and
                        redir not in self.tobrowse and
                            not self.isExcluded(redir)):
                        self.tobrowse.append(redir)

        html_source = data
        bs = BeautifulSoup(html_source)
        # Look for a base tag with an href attribute
        if bs.head:
            for base in bs.head.findAll("base"):
                # BeautifulSoup doesn't work as excepted with the "in" statement, keep this:
                if "href" in base.attrs:
                    # Found a base url, now set it as the current url
                    current = base["href"].split("#")[0]
                    # We don't need destination anchors
                    current = current.split("?")[0]
                    # Get the dirname of the file
                    currentdir = "/".join(current.split("/")[:-1]) + "/"
                    break

        p = LinkParser(url)
        try:
            p.feed(html_source)
        except HTMLParser.HTMLParseError:
            html_source = BeautifulSoup(html_source).prettify()
            if not isinstance(html_source, unicode) and page_encoding is not None:
                html_source = unicode(html_source, page_encoding, errors='ignore')
            try:
                p.reset()
                p.feed(html_source)
            except HTMLParser.HTMLParseError:
                p = LinkParser2(url, self.verbose)
                p.feed(html_source)

        # Sometimes the page is badcoded but the parser doesn't see the error
        # So if we got no links we can force a correction of the page
        if len(p.liens) == 0:
            if page_encoding is not None:
                try:
                    html_source = BeautifulSoup(html_source).prettify(page_encoding)
                    p.reset()
                    p.feed(html_source)
                except UnicodeEncodeError:
                    # The resource is not a valid webpage (for example an image)
                    pass
                except HTMLParser.HTMLParseError:
                    p = LinkParser2(url, self.verbose)
                    p.feed(html_source)

        found_links = p.liens + swf_links + js_links
        for lien in found_links:
            if lien is not None and page_encoding is not None and isinstance(lien, unicode):
                lien = lien.encode(page_encoding, "ignore")
            lien = self.correctlink(lien, current, current_full_url, currentdir, proto, page_encoding)
            if lien is not None:
                if self.__inzone(lien) == 0:
                    # Is the document already visited of forbidden ?
                    lien = HTTP.HTTPResource(lien, encoding=page_encoding, referer=url, link_depth=current_depth+1)
                    if (lien in self.browsed_links or
                        lien in self.tobrowse or
                            self.isExcluded(lien)):
                        pass
                    # TODO : check this
                    elif self.nice > 0:
                        if self.__countMatches(lien) >= self.nice:
                            # don't waste time next time we found it
                            self.excluded.append(lien.url)
                            return False
                        else:
                            self.tobrowse.append(lien)
                    else:
                        # No -> Will browse it soon
                        self.tobrowse.append(lien)
                    # Keep the encoding of the current webpage for the future requests to the link
                    # so we can encode the query string parameters just as a browser would do.
                    # Of course websites encoding may be broken :(
                    self.link_encoding[lien] = page_encoding

        for form in p.forms:
            action = self.correctlink(form[0], current, current_full_url, currentdir, proto, page_encoding)
            if action is None:
                action = current
            if self.__inzone(action) != 0:
                continue

            # urlencode the POST parameters here
            params = form[1]
            post_params = []
            files = []
            for kv in params:
                if isinstance(kv[0], unicode):
                    kv[0] = kv[0].encode(page_encoding, "ignore")

                if isinstance(kv[1], list):
                    fname = kv[1][0]
                    if isinstance(fname, unicode):
                        fname = fname.encode(page_encoding, "ignore")
                    files.append([kv[0], [fname, kv[1][1]]])
                else:
                    if isinstance(kv[1], unicode):
                        kv[1] = kv[1].encode(page_encoding, "ignore")
                    post_params.append([kv[0], kv[1]])

            form_rsrc = HTTP.HTTPResource(action,
                                          method="POST",
                                          post_params=post_params,
                                          file_params=files,
                                          encoding=page_encoding,
                                          referer=url,
                                          link_depth=current_depth+1)
            if (form_rsrc not in self.browsed_forms and
                form_rsrc not in self.tobrowse and
                    not self.isExcluded(form_rsrc)):
                self.tobrowse.append(form_rsrc)
            if files:
                if form_rsrc not in self.uploads:
                    self.uploads.append(form_rsrc)
        # We automatically exclude 404 urls
        if code == "404":
            self.excluded.append(url)
            #return {} # exclude from scan but can be useful for some modules maybe

        return True

    def correctlink(self, lien, current_url, current_full_url, current_directory, protocol, encoding):
        """Transform relatives urls in absolutes ones"""

        if lien is None:
            return current_full_url

        # No destination anchor
        if "#" in lien:
            lien = lien.split("#")[0]

        # No leading or trailing whitespaces
        lien = lien.strip()

        if lien == "":
            return current_full_url

        if lien == "..":
            lien = "../"
        # bad protocols
        llien = lien.lower()
        if (llien.startswith("telnet:") or
            llien.startswith("ftp:") or
            llien.startswith("mailto:") or
            llien.startswith("javascript:") or
            llien.startswith("news:") or
            llien.startswith("file:", 0) or
            llien.startswith("gopher:") or
            # Sublime scheme, don't know what to do with it for the moment
            llien.startswith("subl:") or
                llien.startswith("irc:", 0)):
            return None
        # Good protocols or relatives links
        else:
            # full url, nothing to do :)
            if lien.startswith("http://") or lien.startswith("https://"):
                pass
            else:
                # Protocol relative URLs
                if lien.startswith("//"):
                    lien = protocol + ":" + lien
                # root-url related link
                elif lien[0] == '/':
                    lien = "{0}://{1}{2}".format(protocol, self.server, lien)
                else:
                    # same page + query string
                    if lien[0] == '?':
                        lien = current_url + lien
                    # current_url directory related link
                    else:
                        lien = current_directory + lien

            args = ""
            if "?" in lien:
                lien, args = lien.split("?", 1)
                # if args is a unicode string, encode it according to the
                # charset of the webpage (if known)
                if encoding and isinstance(args, unicode):
                    args = args.encode(encoding, "ignore")

                # a hack for auto-generated Apache directory index
                if args in ["C=D;O=A", "C=D;O=D", "C=M;O=A", "C=M;O=D",
                            "C=N;O=A", "C=N;O=D", "C=S;O=A", "C=S;O=D"]:
                    args = ""

                if "&" in args:
                    args = args.split("&")
                    args = [i for i in args if i != "" and "=" in i]
                    for i in self.bad_params:
                        for j in args:
                            if j.startswith(i + "="):
                                args.remove(j)
                    args = "&".join(args)

            # First part of the url (path) must be encoded with UTF-8
            if isinstance(lien, unicode):
                lien = lien.encode("UTF-8", "ignore")
            lien = urllib.quote(lien, safe='/#%[]=:;$&()+,!?*')

            # remove useless slashes repetitions (expect those from the protocol)
            lien = re.sub("([^:])//+", r"\1/", lien)
            if lien[-2:] == "/.":
                lien = lien[:-1]

            # It should be safe to parse now
            parsed = urlparse.urlparse(lien)
            path = parsed.path

            # links going to a parrent directory (..)
            while re.search("/([~:!,;a-zA-Z0-9\.\-+_]+)/\.\./", path) is not None:
                path = re.sub("/([~:!,;a-zA-Z0-9\.\-+_]+)/\.\./", "/", path)
            while re.search("/\./", path) is not None:
                path = re.sub("/\./", "/", path)
            if path == "":
                path = '/'

            # Fix for path going back up the root directory (eg: http://srv/../../dir/)
            path = re.sub(r'^(/?\.\.//*)*', '',  path)
            if not path.startswith('/'):
                path = '/' + path

            lien = "%s://%s%s" % (parsed.scheme, parsed.netloc, path)
            if args != "":
                # Put back the query part
                lien = "%s?%s" % (lien, args)
            return lien

    @staticmethod
    def __checklink(url):
        """Verify the protocol"""
        if url.startswith("http://") or url.startswith("https://"):
            return 0
        else:
            return 1

    def __inzone(self, url):
        """Make sure the url is under the root url"""
        # Returns 0 if the URL is in zone
        if self.scope == self.SCOPE_PAGE:
            if url == self.scope_url:
                return 0
            else:
                return 1
        if url.startswith(self.scope_url):
            return 0
        else:
            return 1

    def isExcluded(self, http_resource):
        """Return True if the url is not allowed to be scan"""
        match = False
        for regexp in self.excluded:
            if self.__reWildcard(regexp, http_resource.url):
                match = True
        return match

    def __countMatches(self, http_resource):
        """Return the number of known urls matching the pattern of the given url"""
        matches = 0
        for b in self.browsed_links:
            if http_resource.path == b.path and http_resource.method == b.method == "GET":
                qs = http_resource.encoded_params
                u = b.encoded_params
                if http_resource.encoded_get_keys == b.encoded_get_keys:
                    # key and value in the query string
                    if "=" in qs:
                        i = 0
                        for __ in xrange(0, qs.count("=")):
                            start = qs.find("=", i)
                            i = qs.find("&", start)
                            if i != -1:
                                if u.startswith(qs[:start] + "=") and u.endswith(qs[i:]):
                                    matches += 1
                            else:
                                if u.startswith(qs[:start] + "="):
                                    matches += 1
                else:
                    # only a key name is query string (eg: path?key_name)
                    if "&" not in qs and "&" not in u:
                        matches += 1
        return matches

    @staticmethod
    def __reWildcard(regexp, string):
        """Wildcard-based regular expression system"""
        regexp = re.sub("\*+", "*", regexp)
        match = True
        if regexp.count("*") == 0:
            if regexp == string:
                return True
            else:
                return False
        blocks = regexp.split("*")
        start = ""
        end = ""
        if not regexp.startswith("*"):
            start = blocks[0]
        if not regexp.endswith("*"):
            end = blocks[-1]
        if start != "":
            if string.startswith(start):
                blocks = blocks[1:]
            else:
                return False
        if end != "":
            if string.endswith(end):
                blocks = blocks[:-1]
            else:
                return False
        blocks = [block for block in blocks if block != ""]
        if not blocks:
            return match
        for block in blocks:
            i = string.find(block)
            if i == -1:
                return False
            string = string[i + len(block):]
        return match

    def go(self, crawler_file):
        # load of the crawler status if a file is passed to it.
        if crawler_file is not None:
            if self.persister.isDataForUrl(crawler_file) == 1:
                self.persister.loadXML(crawler_file)
                self.tobrowse = self.persister.getToBrose()
                self.browsed_links = self.persister.getLinks()
                self.browsed_forms = self.persister.getForms()
                print(_("File {0} loaded, the scan continues:").format(crawler_file))
                if self.verbose == 2:
                    print(_(" * URLs to browse"))
                    for x in self.tobrowse:
                        print(u"    + {0}".format(x))
                    print(_(" * URLs browsed"))
                    for x in self.browsed_links:
                        print(u"    + {0}".format(x))
            else:
                print(_("File {0} not found, Wapiti will scan again the web site").format(crawler_file))

        # while url list isn't empty, continue browsing
        # if the user stop the scan with Ctrl+C, give him all found urls
        # and they are saved in an XML file
        try:
            while len(self.out_of_scope_urls):
                http_res = self.out_of_scope_urls.pop(0)
                if self.browse(http_res):
                    if self.verbose == 1:
                        sys.stderr.write('.')
                    elif self.verbose == 2:
                        print(http_res)

            while len(self.tobrowse):
                http_res = self.tobrowse.pop(0)
                if (http_res not in self.browsed_links and
                    http_res not in self.browsed_forms and
                        http_res.url not in self.excluded):
                    if self.browse(http_res):
                        if self.verbose == 1:
                            sys.stderr.write('.')
                        elif self.verbose == 2:
                            print(http_res)

                        if http_res.method == "POST":
                            self.browsed_forms.append(http_res)
                        elif http_res.method == "GET":
                            self.browsed_links.append(http_res)

            self.saveCrawlerData()
            print('')
            print(_(" Note"))
            print("========")
            print(_("This scan has been saved in the file {0}/{1}.xml").format(self.persister.CRAWLER_DATA_DIR,
                                                                               self.server))
            print(_("You can use it to perform attacks without scanning again the web site with the \"-k\" parameter"))
        except KeyboardInterrupt:
            self.saveCrawlerData()
            print('')
            print(_(" Note"))
            print("========")
            print(_("Scan stopped, the data has been saved"
                    "in the file {0}/{1}.xml").format(self.persister.CRAWLER_DATA_DIR, self.server))
            print(_("To continue this scan, you should launch Wapiti with the \"-i\" parameter"))
            pass

    def verbosity(self, vb):
        """Set verbosity level"""
        self.verbose = vb

    def printLinks(self):
        """Print found URLs on standard output"""
        self.browsed_links.sort()
        sys.stderr.write("\n+ " + _("URLs") + ":\n")
        for link in self.browsed_links:
            print(link)

    def printForms(self):
        """Print found forms on standard output"""
        if self.browsed_forms:
            sys.stderr.write("\n+ "+_("Forms Info") + ":\n")
            for form in self.browsed_forms:
                print(_("From: {0}").format(form.referer))
                print(_("To: {0}").format(form))
                print('')

    def printUploads(self):
        """Print urls accepting uploads"""
        if self.uploads:
            sys.stderr.write("\n+ " + _("Upload Scripts") + ":\n")
            for up in self.uploads:
                print(up)

    def exportXML(self, filename, encoding="UTF-8"):
        """Export the urls and the forms found in an XML file."""
        xml = minidom.Document()
        items = xml.createElement("items")
        xml.appendChild(items)

        for lien in self.browsed_links:
            get = xml.createElement("get")
            get.setAttribute("url", lien.url)
            items.appendChild(get)

        for form in self.browsed_forms:
            post = xml.createElement("post")
            post.setAttribute("url", form[0])
            post.setAttribute("referer", form[2])

            for k, v in form[1].items():
                var = xml.createElement("var")
                var.setAttribute("name", k)
                var.setAttribute("value", v)
                post.appendChild(var)
            items.appendChild(post)

        fd = open(filename, "w")
        xml.writexml(fd, "    ", "    ", "\n", encoding)
        fd.close()

    def getLinks(self):
        return self.browsed_links

    def getForms(self):
        return self.browsed_forms

    def getUploads(self):
        self.uploads.sort()
        return self.uploads

    def saveCrawlerData(self):
        self.persister.setRootURL(self.root)
        self.persister.setToBrose(self.tobrowse)
        self.persister.setLinks(self.browsed_links)
        self.persister.setForms(self.browsed_forms)
        self.persister.setUploads(self.uploads)
        self.persister.saveXML(os.path.join(self.persister.CRAWLER_DATA_DIR, self.server + '.xml'))


class LinkParser(HTMLParser.HTMLParser):
    """Extract urls in 'a' href HTML tags"""
    def __init__(self, url=""):
        HTMLParser.HTMLParser.__init__(self)
        self.liens = []
        self.forms = []
        self.form_values = []
        self.inform = 0
        self.inscript = 0
        self.current_form_url = url
        self.uploads = []
        self.current_form_method = "get"
        self.url = url
        self.__defaults = {'checkbox':       'default',
                           'color':          '%23adeadb',
                           'date':           '2011-06-08',
                           'datetime':       '2011-06-09T20:35:34.32',
                           'datetime-local': '2011-06-09T22:41',
                           'file':           ['pix.gif', 'GIF89a'],
                           'hidden':         'default',
                           'email':           'wapiti%40mailinator.com',
                           'month':          '2011-06',
                           'number':         '1337',
                           'password':       'letmein',
                           'radio':          'beton', # priv8 j0k3
                           'range':          '37',
                           'search':         'default',
                           'submit':         'submit',
                           'tel':            '0606060606',
                           'text':           'default',
                           'time':           '13:37',
                           'url':            'http://wapiti.sf.net/',
                           'week':           '2011-W24'
                           }
        # This is ugly but let's keep it while there is not a js parser
        self.common_js_strings = ["Msxml2.XMLHTTP", "application/x-www-form-urlencoded", ".php", "text/xml",
                                  "about:blank", "Microsoft.XMLHTTP", "text/plain", "text/javascript",
                                  "application/x-shockwave-flash"]

    def handle_starttag(self, tag, attrs):
        tmpdict = {}
        for k, v in attrs:
            if v is None:
                continue
            if not k.lower() in tmpdict:
                tmpdict[k.lower()] = v
        if tag.lower() in ['a', 'link']:
            if "href" in tmpdict:
                if tmpdict['href'].lower().startswith("javascript:"):
                    self.liens.extend(lamejs.lamejs(tmpdict["href"].split(':', 1)[1]).getLinks())
                else:
                    self.liens.append(tmpdict['href'])

        if tag.lower() == 'form':
            self.inform = 1
            self.form_values = []
            self.current_form_url = self.url
            if "action" in tmpdict:
                if tmpdict['action'].lower().startswith("javascript"):
                    self.liens.extend(lamejs.lamejs(tmpdict["action"].split(':', 1)[1]).getLinks())
                self.liens.append(tmpdict['action'])
                self.current_form_url = tmpdict['action']

            # Forms use GET method by default
            self.current_form_method = "get"
            if "method" in tmpdict:
                if tmpdict["method"].lower() == "post":
                    self.current_form_method = "post"

        if tag.lower() == 'input':
            if self.inform == 1:
                if "type" not in tmpdict:
                    tmpdict["type"] = "text"
                if "name" in tmpdict:
                    if tmpdict['type'].lower() in self.__defaults:
                        # use the value from the form or use our default value
                        if "value" in tmpdict and tmpdict["value"] != "":
                            val = tmpdict["value"]
                        else:
                            val = self.__defaults[tmpdict['type'].lower()]
                        self.form_values.append([tmpdict['name'], val])

                    if tmpdict['type'].lower() == "image":
                        self.form_values.append([tmpdict['name'] + ".x", "1"])
                        self.form_values.append([tmpdict['name'] + ".y", "1"])

            if "formaction" in tmpdict:
                self.liens.append(tmpdict['formaction'])

        if tag.lower() in ["textarea", "select"]:
            if self.inform == 1:
                if "name" in tmpdict:
                    self.form_values.append([tmpdict['name'], u'on'])

        if tag.lower() in ["frame", "iframe"]:
            if "src" in tmpdict:
                self.liens.append(tmpdict['src'])

        if tag.lower() in ["img", "embed", "track", "source"]:
            if "src" in tmpdict:
                if "?" in tmpdict['src'] or tmpdict['src'].endswith(".swf"):
                    self.liens.append(tmpdict['src'])

        if tag.lower() == "script":
            self.inscript = 1
            if "src" in tmpdict:
                # if "?" in tmpdict['src']:
                self.liens.append(tmpdict['src'])

        if tag.lower() == "meta":
            if "http-equiv" in tmpdict and "content" in tmpdict:
                if tmpdict["http-equiv"].lower() == "refresh":
                    content_str = tmpdict["content"].lower()
                    url_eq_idx = content_str.find("url=")
                    if url_eq_idx >= 0:
                        self.liens.append(tmpdict["content"][url_eq_idx + 4:])

    def handle_endtag(self, tag):
        if tag.lower() == 'form':
            self.inform = 0
            if self.current_form_method == "post":
                self.forms.append((self.current_form_url, self.form_values))
            else:
                l = ["=".join([k, v]) for k, v in self.form_values]
                l.sort()
                self.liens.append(self.current_form_url.split("?")[0] + "?" + "&".join(l))
        if tag.lower() == 'script':
            self.inscript = 0

    def handle_data(self, data):
        if self.inscript:
            allowed_ext = [".php", ".asp", ".xml", ".js", ".json", ".jsp"]
            self.liens.extend(lamejs.lamejs(data).getLinks())
            candidates = re.findall(r'"([A-Za-z0-9_=#&%\.\+\?/-]*)"', data)
            candidates += re.findall(r"'([A-Za-z0-9_=#&%\.\+\?/-]*)'", data)
            for jstr in candidates:
                if jstr not in self.common_js_strings:
                    for ext in allowed_ext:
                        if ext in jstr:
                            self.liens.append(jstr)


class LinkParser2(object):
    verbose = 0

    """Extract urls in 'a' href HTML tags"""
    def __init__(self, url="", verb=0):
        self.liens = []
        self.forms = []
        self.form_values = []
        self.inform = 0
        self.current_form_url = ""
        self.uploads = []
        self.current_form_method = "get"
        self.verbose = verb

    @staticmethod
    def __findTagAttributes(tag):
        att_double = re.findall('<\w*[ ]| *(.*?)[ ]*=[ ]*"(.*?)"[ +|>]', tag)
        att_single = re.findall('<\w*[ ]| *(.*?)[ ]*=[ ]*\'(.*?)\'[ +|>]', tag)
        att_none = re.findall('<\w*[ ]| *(.*?)[ ]*=[ ]*["|\']?(.*?)["|\']?[ +|>]', tag)
        att_none.extend(att_single)
        att_none.extend(att_double)
        return att_none

    def feed(self, html_source):
        html_source = html_source.replace("\n", "")
        html_source = html_source.replace("\r", "")
        html_source = html_source.replace("\t", "")

        links = re.findall('<a.*?>', html_source)
        link_attributes = []
        for link in links:
            link_attributes.append(self.__findTagAttributes(link))

        #Finding all the forms: getting the text from "<form..." to "...</form>"
        #the array forms will contain all the forms of the page
        forms = re.findall('<form.*?>.*?</form>', html_source)
        forms_attributes = []
        for form in forms:
            forms_attributes.append(self.__findTagAttributes(form))

        #Processing the forms, obtaining the method and all the inputs
        #Also finding the method of the forms
        inputs_in_forms = []
        text_areas_in_forms = []
        selects_in_forms = []
        for form in forms:
            inputs_in_forms.append(re.findall('<input.*?>', form))
            text_areas_in_forms.append(re.findall('<textarea.*?>', form))
            selects_in_forms.append(re.findall('<select.*?>', form))

        #Extracting the attributes of the <input> tag as XML parser
        inputs_attributes = []
        for i in xrange(len(inputs_in_forms)):
            inputs_attributes.append([])
            for inputt in inputs_in_forms[i]:
                inputs_attributes[i].append(self.__findTagAttributes(inputt))

        selects_attributes = []
        for i in xrange(len(selects_in_forms)):
            selects_attributes.append([])
            for select in selects_in_forms[i]:
                selects_attributes[i].append(self.__findTagAttributes(select))

        textareas_attributes = []
        for i in xrange(len(text_areas_in_forms)):
            textareas_attributes.append([])
            for textArea in text_areas_in_forms[i]:
                textareas_attributes[i].append(self.__findTagAttributes(textArea))

        if self.verbose == 3:
            print('')
            print('')
            print(_("Forms"))
            print("=====")
            for i in xrange(len(forms)):
                print(_("Form {0}").format(str(i)))
                tmpdict = {}
                for k, v in dict(forms_attributes[i]).items():
                    tmpdict[k.lower()] = v
                print(_(" * Method:  {0}").format(self.__decode_htmlentities(tmpdict['action'])))
                print(_(" * Intputs:"))
                for j in xrange(len(inputs_in_forms[i])):
                    print(u"    + " + inputs_in_forms[i][j])
                    for att in inputs_attributes[i][j]:
                        print(u"       - " + str(att))
                print(_(" * Selects:"))
                for j in xrange(len(selects_in_forms[i])):
                    print(u"    + " + selects_in_forms[i][j])
                    for att in selects_attributes[i][j]:
                        print(u"       - " + str(att))
                print(_(" * TextAreas:"))
                for j in xrange(len(text_areas_in_forms[i])):
                    print(u"    + " + text_areas_in_forms[i][j])
                    for att in textareas_attributes[i][j]:
                        print(u"       - " + str(att))
            print('')
            print(_("URLS"))
            print("====")

        for i in xrange(len(links)):
            tmpdict = {}
            for k, v in dict(link_attributes[i]).items():
                tmpdict[k.lower()] = v
            if "href" in tmpdict:
                self.liens.append(self.__decode_htmlentities(tmpdict['href']))
                if self.verbose == 3:
                    print(self.__decode_htmlentities(tmpdict['href']))

        for i in xrange(len(forms)):
            tmpdict = {}
            for k, v in dict(forms_attributes[i]).items():
                tmpdict[k.lower()] = v
            self.form_values = []
            if "action" in tmpdict:
                self.liens.append(self.__decode_htmlentities(tmpdict['action']))
                self.current_form_url = self.__decode_htmlentities(tmpdict['action'])

            # Forms use GET method by default
            self.current_form_method = "get"
            if "method" in tmpdict:
                if tmpdict["method"].lower() == "post":
                    self.current_form_method = "post"

            for j in xrange(len(inputs_attributes[i])):
                tmpdict = {}
                for k, v in dict(inputs_attributes[i][j]).items():
                    tmpdict[k.lower()] = v
                    if "type" not in tmpdict:
                        tmpdict["type"] = "text"
                    if "name" in tmpdict:
                        if tmpdict['type'].lower() in \
                            ['text', 'password', 'radio', 'checkbox', 'hidden',
                             'submit', 'search']:
                            # use default value if present or set it to 'on'
                            if "value" in tmpdict:
                                if tmpdict["value"] != "":
                                    val = tmpdict["value"]
                                else:
                                    val = u"on"
                            else:
                                val = u"on"
                            self.form_values.append([tmpdict['name'], val])
                        if tmpdict['type'].lower() == "file":
                            self.uploads.append(self.current_form_url)

            for j in xrange(len(textareas_attributes[i])):
                tmpdict = {}
                for k, v in dict(textareas_attributes[i][j]).items():
                    tmpdict[k.lower()] = v
                if "name" in tmpdict:
                    self.form_values.append([tmpdict['name'], u'on'])

            for j in xrange(len(selects_attributes[i])):
                tmpdict = {}
                for k, v in dict(selects_attributes[i][j]).items():
                    tmpdict[k.lower()] = v
                if "name" in tmpdict:
                    self.form_values.append([tmpdict['name'], u'on'])

            if self.current_form_method == "post":
                self.forms.append((self.current_form_url, self.form_values))
            else:
                l = ["=".join([k, v]) for k, v in self.form_values]
                l.sort()
                self.liens.append(self.current_form_url.split("?")[0] + "?" + "&".join(l))

    @staticmethod
    def __substitute_entity(match):
        ent = match.group(2)
        if match.group(1) == "#":
            return unichr(int(ent))
        else:
            cp = n2cp.get(ent)

            if cp:
                return unichr(cp)
            else:
                return match.group()

    def __decode_htmlentities(self, string):
        entity_re = re.compile("&(#?)(\d{1,5}|\w{1,8});")
        return entity_re.subn(self.__substitute_entity, string)[0]

    def reset(self):
        self.liens = []
        self.forms = []
        self.form_values = []
        self.inform = 0
        self.current_form_url = ""
        self.uploads = []
        self.current_form_method = "get"

if __name__ == "__main__":
    def _(text):
        return text
    try:
        auth = []
        xmloutput = ""
        crawlerFile = None

        if len(sys.argv) < 2:
            print(lswww.__doc__)
            sys.exit(0)
        if '-h' in sys.argv or '--help' in sys.argv:
            print(lswww.__doc__)
            sys.exit(0)
        myls = lswww(sys.argv[1])
        myls.verbosity(1)
        try:
            opts, args = getopt.getopt(sys.argv[2:],
                                       "hp:s:x:c:a:r:v:t:n:e:ib:",
                                       ["help", "proxy=", "start=", "exclude=", "cookie=", "auth=",
                                        "remove=", "verbose=", "timeout=", "nice=", "export=", "continue",
                                        "scope="])
        except getopt.GetoptError, e:
            print(e)
            sys.exit(2)
        for o, a in opts:
            if o in ("-h", "--help"):
                print(lswww.__doc__)
                sys.exit(0)
            if o in ("-s", "--start"):
                if a.startswith("http://") or a.startswith("https://"):
                    myls.addStartURL(a)
            if o in ("-x", "--exclude"):
                if a.startswith("http://") or a.startswith("https://"):
                    myls.addExcludedURL(a)
            if o in ("-p", "--proxy"):
                    myls.setProxy(a)
            if o in ("-c", "--cookie"):
                myls.setCookieFile(a)
            if o in ("-r", "--remove"):
                myls.addBadParam(a)
            if o in ("-a", "--auth"):
                if "%" in a:
                    auth = [a.split("%")[0], a.split("%")[1]]
                    myls.setAuthCredentials(auth)
            if o in ("-v", "--verbose"):
                if str.isdigit(a):
                    myls.verbosity(int(a))
            if o in ("-t", "--timeout"):
                if str.isdigit(a):
                    myls.setTimeOut(int(a))
            if o in ("-n", "--nice"):
                if str.isdigit(a):
                    myls.setNice(int(a))
            if o in ("-e", "--export"):
                xmloutput = a
            if o in ("-b", "--scope"):
                myls.setScope(a)
            if o in ("-i", "--continue"):
                crawlerPersister = CrawlerPersister()
                crawlerFile = os.path.join(crawlerPersister.CRAWLER_DATA_DIR, sys.argv[1].split("://")[1] + '.xml')
        try:
            opts, args = getopt.getopt(sys.argv[2:],
                                       "hp:s:x:c:a:r:v:t:n:e:i:b:",
                                       ["help", "proxy=", "start=", "exclude=", "cookie=",
                                        "auth=", "remove=", "verbose=", "timeout=", "nice=",
                                        "export=", "continue=", "scope="])
        except getopt.GetoptError, e:
            print("GetOpt error: {0}".format(e))
        for o, a in opts:
            if o in ("-i", "--continue"):
                if a != '' and a[0] != '-':
                    crawlerFile = a

        myls.go(crawlerFile)
        myls.printLinks()
        myls.printForms()
        myls.printUploads()
        if xmloutput != "":
            myls.exportXML(xmloutput)
    except SystemExit:
        pass
