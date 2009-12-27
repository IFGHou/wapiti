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
import urllib2
import urlparse
import sys, socket, lswww, HTMLParser
import libcookie
import os
import BeautifulSoup

if "_" not in dir():
  def _(s):
    return s

if len(sys.argv) != 3:
  sys.stderr.write("Usage: python getcookie.py <cookie_file> <url_with_form>\n")
  sys.exit(1)

COOKIEFILE = sys.argv[1]
url = sys.argv[2]

# Some websites/webapps like Webmin send a first cookie to see if the browser support them
# so we must collect these test-cookies during authentification.
lc = libcookie.libcookie(url)
lc.loadfile(COOKIEFILE)
lc.delete(urlparse.urlparse(url)[1])

current = url.split("#")[0]
current = current.split("?")[0]
currentdir = "/".join(current.split("/")[:-1]) + "/"
proto = url.split("://")[0]
agent =  {'User-agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}

req = urllib2.Request(url)
socket.setdefaulttimeout(6)
try:
  fd = urllib2.urlopen(req)
except IOError:
  print _("Error getting url")
  sys.exit(1)

try:
  htmlSource = fd.read()
except socket.timeout:
  print _("Error fetching page")
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
    pass

lc.add(fd, htmlSource)

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
print _("Please enter values for the folling form :")
print "url = " + myls.correctlink(form[0], current, currentdir, proto)

d = {}
for field, value in form[1].items():
  str = raw_input(field + " (" + value + ") : ")
  d[field] = str

form[1].update(d)
url = myls.correctlink(form[0], current, currentdir, proto)

server = urlparse.urlparse(url)[1]
script = urlparse.urlparse(url)[2]
if urlparse.urlparse(url)[4] != "":
  script += "?" + urlparse.urlparse(url)[4]
params = urllib.urlencode(form[1])

txheaders =  {'User-agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
              'Referer' : sys.argv[2]}

path = os.path.dirname(urllib2.urlparse.urlparse(url)[2])
txheaders.update( lc.headers_url(url) )

try:
    req = urllib2.Request(url, params, txheaders)
    handle = urllib2.urlopen(req)
except IOError, e:
    print _("Error getting url"), url
    sys.exit(1)

htmlSource = handle.read()
lc.add(handle, htmlSource)
lc.save(COOKIEFILE)
