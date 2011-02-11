#!/usr/bin/env python

# Copyright (C) 2006 Nicolas Surribas
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

import urllib
import urlparse
import sys
import lswww
import HTMLParser
import libcookie
import BeautifulSoup
import httplib2
import getopt

if "_" not in dir():
  def _(s):
    return s

if len(sys.argv) < 3:
  sys.stderr.write("Usage: python getcookie.py <cookie_file> <url_with_form> [options]\n\n"+
                   "Supported options are:\n"+
                   "-p <url_proxy>\n"+
                   "--proxy <url_proxy>\n"+
                   "	To specify a proxy\n"+
                   "    Example: -p http://proxy:port/\n\n")
  sys.exit(1)

TIMEOUT = 6
COOKIEFILE = sys.argv[1]
url = sys.argv[2]
proxy = None

try:
  opts, args = getopt.getopt(sys.argv[3:], "p:",
      ["proxy="])
except getopt.GetoptError, e:
  print e
  sys.exit(2)
for o, a in opts:
  if o in ("-p", "--proxy"):
    proxy = a

# Some websites/webapps like Webmin send a first cookie to see if the browser support them
# so we must collect these test-cookies during authentification.
lc = libcookie.libcookie(url)
lc.loadfile(COOKIEFILE)
lc.delete(urlparse.urlparse(url)[1])

current = url.split("#")[0]
current = current.split("?")[0]
currentdir = "/".join(current.split("/")[:-1]) + "/"
proto = url.split("://")[0]

txheaders =  {'User-agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}

if proxy != None and proxy != "":
  (proxy_type, proxy_usr, proxy_pwd, proxy_host, proxy_port,
   path, query, fragment) = httplib2.parse_proxy(proxy)
  proxy = httplib2.ProxyInfo(proxy_type, proxy_host, proxy_port,
      proxy_user = proxy_usr, proxy_pass = proxy_pwd)

h = httplib2.Http(timeout = TIMEOUT, proxy_info = proxy)
try:
    resp, htmlSource = h.request(url, headers=txheaders)
except httplib2.HTTPTimeout:
    print _("Error getting url"), url
    sys.exit(1)

p = lswww.linkParser(url)
try:
  p.feed(htmlSource)
except HTMLParser.HTMLParseError, err:
  htmlSource = BeautifulSoup.BeautifulSoup(htmlSource).prettify()
  try:
    p.reset()
    p.feed(htmlSource)
  except HTMLParser.HTMLParseError, err:
    p = lswww.linkParser2(url)
    p.feed(htmlSource)

lc.addHttplib(resp, htmlSource)

if len(p.forms) == 0:
  print _("No forms found in this page !")
  sys.exit(1)

myls = lswww.lswww(url)
i = 0
nchoice = 0
if len(p.forms) > 1:
  print _("Choose the form you want to use :")
  for form in p.forms:
    print
    print "%d) %s" % (i, myls.correctlink(form[0], current, currentdir, proto))
    for field, value in form[1].items():
      print "\t" + field + " (" + value + ")"
    i += 1
  ok = False
  while ok == False:
    choice = raw_input(_("Enter a number : "))
    if choice.isdigit():
      nchoice = int(choice)
      if nchoice < i and nchoice >= 0:
        ok = True

form = p.forms[nchoice]
print _("Please enter values for the following form: ")
print "url = " + myls.correctlink(form[0], current, currentdir, proto)

d = {}
for field, value in form[1].items():
  str = raw_input(field + " (" + value + ") : ")
  d[field] = str

form[1].update(d)
url = myls.correctlink(form[0], current, currentdir, proto)

params = urllib.urlencode(form[1])

txheaders =  {'User-agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
              'Content-type': 'application/x-www-form-urlencoded'}
txheaders.update( lc.headers_url(url) )

try:
    resp, content = h.request(url, "POST", headers=txheaders, body=params)
except httplib2.HTTPTimeout:
    print _("Error getting url"), url
    sys.exit(1)

lc.addHttplib(resp, content)
lc.save(COOKIEFILE)
