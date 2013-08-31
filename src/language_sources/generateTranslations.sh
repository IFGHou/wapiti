rm ../config/language/fr/LC_MESSAGES/wapiti.mo 2> /dev/null
rm ../config/language/en/LC_MESSAGES/wapiti.mo 2> /dev/null
rm ../config/language/es/LC_MESSAGES/wapiti.mo 2> /dev/null
msgfmt fr.po -o ../config/language/fr/LC_MESSAGES/wapiti.mo
msgfmt en.po -o ../config/language/en/LC_MESSAGES/wapiti.mo
msgfmt es.po -o ../config/language/es/LC_MESSAGES/wapiti.mo
