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
import sys
import urllib2, urllib
import libcookie

if "_" not in dir():
  def _(s):
    return s

if len(sys.argv) < 4:
  sys.stderr.write("Usage python cookie.py <cookie_file> <url> <arg1=val1> ...\n")
  sys.exit(1)

cookiefile = sys.argv[1]
url = sys.argv[2]
data = sys.argv[3:]
liste = []
for l in data:
  liste.append( tuple( l.split("=") ) )
params = urllib.urlencode(liste)

txheaders =  {'User-agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}

try:
    req = urllib2.Request(url, params, headers=txheaders)
    handle = urllib2.urlopen(req)
except IOError, e:
    print _("Error getting url"), url
    print e
    sys.exit(1)

lc = libcookie.libcookie(url)
lc.loadfile(cookiefile)
lc.add(handle, handle.read())
lc.save(cookiefile)
