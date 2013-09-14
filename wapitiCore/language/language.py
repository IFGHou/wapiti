#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2008-2013 Nicolas Surribas
#
# Original author :
# David del Pozo
# Alberto Pastor
# Copyright (C) 2008 Informatica Gesfor
# ICT Romulus (http://www.ict-romulus.eu)
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
import os
import locale
import gettext
from pkg_resources import resource_filename


class Language(object):
    """
    This class configures the internationalization of Wapiti,
    retrieving the texts from the files where is the translation.
    It establishes the funcion "_" for translating.
    To do it, the method "configure" should be invoked.
    """

    AVAILABLE_LANGS = ["es", "en", "fr"]

    BASE_DIR = resource_filename('wapitiCore', '')
    LANG_PATH = os.path.join(BASE_DIR, "config", "language")

    def configure(self, lang=None):
        """
        Configures the funcion "_" for translating the texts of Wapiti,
        this method loads the language indicated as parameter or if the
        parameter is not specified, it will take the default language
        of the operating system.
        """
        if lang is None:
            # if lang is not specified, default language is used
            defLocale = locale.getdefaultlocale()
            langCounty = defLocale[0]   # en_UK
            lang = langCounty[:2]  # en
        if lang not in self.AVAILABLE_LANGS:
            # if lang is not between the lang translated, english by default
            print("Oups! No translations found for your language... Using english.")
            print("Please send your translations for improvements.")
            print("===============================================================")
            lang = 'en'
        lan = gettext.translation('wapiti',
                                  self.LANG_PATH,
                                  languages=[lang],
                                  codeset="UTF-8")
        lan.install(unicode=1)

        #funcion which translates
        def _(key):
            return lan.lgettext(key)
