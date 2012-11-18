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
import urllib
import jsoncookie
import requests

if "_" not in dir():
  def _(s):
    return s

if len(sys.argv) < 3:
  sys.stderr.write("Usage python cookie.py <cookie_file> <url> <arg1=val1> ...\n")
  sys.exit(1)

cookiefile = sys.argv[1]
url = sys.argv[2]
liste = []

if len(sys.argv) > 3:
  data = sys.argv[3:]
  for l in data:
    liste.append( tuple( l.split("=") ) )
params = urllib.urlencode(liste)

txheaders =  {'user-agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}

try:
  if params:
    txheaders['content-type'] = 'application/x-www-form-urlencoded'
    r = requests.post(url, data=params, headers=txheaders)
  else:
    r = requests.get(url, headers=txheaders)
except IOError, e:
    print _("Error getting url"), url
    print e
    sys.exit(1)

jc = jsoncookie.jsoncookie()
jc.open(cookiefile)
jc.addcookies(r.cookies)
jc.dump()
jc.close()
