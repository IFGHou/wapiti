#!/usr/bin/env python

# Copyright (C) 2009 Nicolas Surribas
#
# This file is part of Wapiti.
#
# Wapiti is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Wapiti is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

import os, sys
import urllib2
from xml.dom import minidom
import re
import time
import BeautifulSoup

class libcookie:

  target = ""
  dom = None
  url = ""
  cookies = None

  def __init__(self, url):
    self.url = url
    self.target = urllib2.httplib.urlsplit(url).hostname

  def loadfile(self, cookiefile=""):
    if cookiefile == "":
      return

    try:
      self.dom = minidom.parse(cookiefile)
      self.cookies = self.dom.firstChild
    except IOError, err:
      print "File not found, creating..."
      self.dom = minidom.Document()
      self.cookies = self.dom.createElement("cookies")
      self.dom.appendChild(self.cookies)

  def add_node(self,cookie_dict):
    # no domain is set in the cookie
    if cookie_dict["domain"] == "":
      # working with an IP address
      if re.match("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", self.target):
        nodes = [node for node in self.cookies.getElementsByTagName("domain") if node.hasAttribute("name") and node.getAttribute("name") == self.target]
        if len(nodes) == 0:
          node = self.dom.createElement("domain")
          node.setAttribute("name", self.target)
          self.cookies.appendChild(node)
        else:
          node = nodes[0]

        for biscuit in node.getElementsByTagName("cookie"):
          if biscuit.getAttribute("name") == cookie_dict["name"] and biscuit.getAttribute("path") == cookie_dict["path"]:
            node.removeChild(biscuit)

        # here we are in the good domain node
        cnode = self.dom.createElement("cookie")
        cnode.setAttribute("name", cookie_dict["name"])
        cnode.setAttribute("value", cookie_dict["value"])
        cnode.setAttribute("version", cookie_dict["version"])
        # keep some space
        if cookie_dict["expires"] != None:
          cnode.setAttribute("expires", str(cookie_dict["expires"]))
        if cookie_dict["path"] != "":
          cnode.setAttribute("path", cookie_dict["path"])

        # verifs a faire ici : vider la node si besoin avant
        node.appendChild(cnode)

      # working with a hostname
      else:
        cookie_dict["domain"] = self.target

    # a domain is defined in the cookie
    if cookie_dict["domain"] != "":
      domains = [x for x in cookie_dict["domain"].split(".") if x != ""]

      curr = self.cookies
      while domains != []:
        domain = domains.pop(-1)

        nodes = [node for node in curr.getElementsByTagName("domain") if node.hasAttribute("name") and node.getAttribute("name") == domain]
        if len(nodes) == 0:
          # oups... we must create all subdomain nodes and break the loop
          node = self.dom.createElement("domain")
          node.setAttribute("name", domain)
          curr.appendChild(node)
        else:
          node = nodes[0]

        curr = node

        if domains == []:
          for biscuit in curr.getElementsByTagName("cookie"):
            if biscuit.getAttribute("name") == cookie_dict["name"]:
              curr.removeChild(biscuit)

          # here we are in the good domain node
          cnode = self.dom.createElement("cookie")
          cnode.setAttribute("name", cookie_dict["name"])
          cnode.setAttribute("value", cookie_dict["value"])
          cnode.setAttribute("version", cookie_dict["version"])
          # keep some space
          if cookie_dict["expires"] != None:
            cnode.setAttribute("expires", str(cookie_dict["expires"]))
          if cookie_dict["path"] != "":
            cnode.setAttribute("path", cookie_dict["path"])

          # verifs a faire ici : vider la node si besoin avant
          curr.appendChild(cnode)

  def add(self, handle, page = ""):
    ref_date = time.time()
    tmp_date = ""
    if len(handle.headers.getheaders("date")) == 1:
      tmp_date = handle.headers.getheaders("date")[0]
      for regexp in ["%a, %d-%b-%Y %H:%M:%S %Z",
          "%a %b %d %H:%M:%S %Y %Z",
          "%a, %b %d %H:%M:%S %Y %Z",
          "%a, %d %b %Y %H:%M:%S %Z"]:
        try:
          ref_date = time.mktime( time.strptime(tmp_date, regexp) )
        except ValueError:
          continue

    if handle.headers.getheaders("set-cookie2") != []:
      version = "2"
    else:
      version = "0"

    for cook in handle.headers.getheaders("set-cookie") + handle.headers.getheaders("set-cookie2"):
      name = ""
      value = ""
      expires = None
      domain = ""
      path = ""
      max_age = None

      brk = 0

      if cook.find("=") >= 0:
        tuples = [x.strip() for x in cook.split(";")]
        name, value = tuples.pop(0).split("=", 1)
        name = name.strip()
        value = value.strip()
        if value[0] == '"' and value[-1] == '"':
          value = value[1:-1]

        for tupl in tuples:
          if tupl.find("=") > 0:
            k, v = tupl.split("=", 1)
            k = k.strip().lower()
            v = v.strip()

            if v[0] == '"' and v[-1] == '"':
              v = v[1:-1]

            if k == "path":
              path = v

            if k == "expires":
              for regexp in ["%a, %d-%b-%Y %H:%M:%S %Z",
                  "%a %b %d %H:%M:%S %Y %Z",
                  "%a, %b %d %H:%M:%S %Y %Z",
                  "%a, %d %b %Y %H:%M:%S %Z"]:
                try:
                  expires = time.mktime( time.strptime(v, regexp) )
                except ValueError:
                  continue

              if ref_date > expires:
                brk = 1

            if k == "comment":
              print "Comment:", v

            if k == "max-age":
              max_age = int(v)
              if max_age == 0:
                brk = 1
              else:
                expires = ref_date + max_age

            if k == "domain":
              domain = v
            
            if k == "version" and version == "0":
              version = "1"

          if tupl.find("secure") >= 0:
            pass

        if brk == 1:
          break

        print name, "=", value

        if path == "":
          path = os.path.dirname(urllib2.urlparse.urlparse(self.url)[2])
          if not path.endswith("/"):
            path = path + "/"

        print name, "=", value
        self.add_node(
            {"name":name,
             "value":value,
             "domain": domain,
             "path":path,
             "expires": expires,
             "version": version
             })

      else:
        print cook

    if handle.headers.getheaders("set-cookie") + handle.headers.getheaders("set-cookie2") == []:
      if page != "":
        soup = BeautifulSoup.BeautifulSoup(page)
        meta = soup.find("meta", {'http-equiv': lambda v: v != None and v.lower()=='set-cookie'})
        if meta != None:
          cook = meta["content"]
          name = ""
          value = ""
          expires = None
          domain = ""
          path = ""
          max_age = None
          expired = False

          if cook.find("=") >= 0:
            tuples = [x.strip() for x in cook.split(";")]
            name, value = tuples.pop(0).split("=", 1)
            name = name.strip()
            value = value.strip()
            if value[0] == '"' and value[-1] == '"':
              value = value[1:-1]

            for tupl in tuples:
              if tupl.find("=") > 0:
                k, v = tupl.split("=", 1)
                k = k.strip().lower()
                v = v.strip()

                if v[0] == '"' and v[-1] == '"':
                  v = v[1:-1]

                if k == "path":
                  path = v

                if k == "expires":
                  for regexp in ["%a, %d-%b-%Y %H:%M:%S %Z",
                      "%a %b %d %H:%M:%S %Y %Z",
                      "%a, %b %d %H:%M:%S %Y %Z",
                      "%a, %d %b %Y %H:%M:%S %Z"]:
                    try:
                      expires = time.mktime( time.strptime(v, regexp) )
                    except ValueError:
                      continue

                  if ref_date > expires:
                    expired = True

                if k == "comment":
                  print "Comment:", v

                if k == "max-age":
                  max_age = int(v)
                  if max_age == 0:
                    expired = True
                  else:
                    expires = ref_date + max_age

                if k == "domain":
                  domain = v
                
                if k == "version" and version == "0":
                  version = "1"

              if tupl.find("secure") >= 0:
                pass

            if path == "":
              path = os.path.dirname(urllib2.urlparse.urlparse(self.url)[2])
              if not path.endswith("/"):
                path = path + "/"

            if expired == False:
              print name, "=", value
              self.add_node(
                  {"name":name,
                   "value":value,
                   "domain": domain,
                   "path":path,
                   "expires": expires,
                   "version": version
                   })

  def delete(self, hostname):
    if self.cookies == None:
      return
    curr = self.cookies
    found = 1

    if re.match("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", hostname):
      nodes = [node for node in self.cookies.getElementsByTagName("domain") if node.hasAttribute("name") and node.getAttribute("name") == hostname]
      if len(nodes) == 0:
        return {}
      else:
        curr = nodes[0]
    else:
      domains = hostname.split(".")

      while domains != []:
        domain = domains.pop(-1)
        nodes = [node for node in curr.getElementsByTagName("domain") if node.hasAttribute("name") and node.getAttribute("name") == domain]
        if len(nodes) != 0:
          curr = nodes[0]
        else:
          found = 0

    if found == 1:
      for x in curr.childNodes:
        curr.removeChild(x)
    #  self.cookies.removeChild(curr) # a NotFoundErr was raised

  def headers(self, hostname, path):
    if self.cookies == None:
      return {}
    curr = self.cookies
    cookie_str = ""
    version_min = 2
    found = 1

    if re.match("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", hostname):
      nodes = [node for node in self.cookies.getElementsByTagName("domain") if node.hasAttribute("name") and node.getAttribute("name") == hostname]
      if len(nodes) == 0:
        return {}
      else:
        curr = nodes[0]
    else:
      domains = hostname.split(".")
      subdomain = 0
      if len(domains) > 2:
        subdomain = 1

      while domains != []:
        domain = domains.pop(-1)
        nodes = [node for node in curr.getElementsByTagName("domain") if node.hasAttribute("name") and node.getAttribute("name") == domain]
        if len(nodes) != 0:
          curr = nodes[0]
        else:
          found = 0

        # work on subdomain cookies
        if subdomain == 1 and len(domains) == 1:
          # we make a check on parentNode to make sure it will search only direct childs nodes
          for biscuit in [x for x in curr.getElementsByTagName("cookie") if x.parentNode == curr]:
            if int( biscuit.getAttribute("version") ) < version_min:
              version_min = int( biscuit.getAttribute("version") )
            cookie_str += biscuit.getAttribute("name") + '="' + biscuit.getAttribute("value") + '"; '
            cookie_str += '$Path="' + biscuit.getAttribute("path") + '"; '
            cookie_str += '$Domain=".' + ".".join( hostname.split(".")[1:] ) + '"; '

    if found == 1:
      biscuits = [x for x in curr.getElementsByTagName("cookie") if path.startswith( x.getAttribute("path") ) ]
      for biscuit in biscuits:
        if int( biscuit.getAttribute("version") ) < version_min:
          version_min = int( biscuit.getAttribute("version") )
        cookie_str += biscuit.getAttribute("name") + '="' + biscuit.getAttribute("value") + '"; '
        cookie_str += '$Path="' + biscuit.getAttribute("path") + '"; '

    if cookie_str == "":
      return {}

    if cookie_str.endswith("; "):
      cookie_str = cookie_str[:-2]

    # Old Netscape cookies : no $Version, no path neither domain.
    # Add a Cookie2 header for information
    if version_min == 0:
      cookie_str = ";".join( [x for x in cookie_str.split(";") if not x.startswith(" $")] )
      cookie_str = cookie_str.replace('"','')
      return {"Cookie": cookie_str, "Cookie2": '$Version="1"'} 

    # RFC 2109 and RFC 2965 cookies
    else:
      cookie_str = '$Version="1"; ' + cookie_str

    return {"Cookie": cookie_str}

  def headers_url(self, url):
    hst = urllib2.urlparse.urlparse(url)[1]
    pth = os.path.dirname(urllib2.urlparse.urlparse(url)[2]) + "/"
    return self.headers(hst, pth)

  def save(self, cookiefile):
    fd = open(cookiefile,"w")
    fd.write( "\n".join( [x for x in self.dom.toprettyxml(indent="  ", encoding="UTF-8").split("\n") if x.strip() !="" ] ) )
    fd.close()
