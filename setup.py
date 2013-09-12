#!/usr/bin/python
from setuptools import setup, find_packages
import os
import sys

VERSION = "SVN"
DOC_DIR = "/usr/local/share/doc/packages/wapiti"


#class wapiti_install_lib(install_lib):
#    def run(self):
#        # Remove useless files
#        os.remove(os.path.join(self.build_dir, 'wapiti', 'wapiti.py'))
#        install_lib.run(self)
#
#
#class wapiti_install_scripts(install_scripts):
#    def run(self):
#        install_scripts.run(self)
#        # Rename wapiti.py to wapiti
#        os.rename(os.path.join(self.install_dir, 'wapiti.py'), os.path.join(self.install_dir, 'wapiti'))


# Build file lists
def build_file_list(results, dest, root, src=""):
    cwd = os.getcwd()
    if src != "":
        os.chdir(src)
    for root, dirs, files in os.walk(root):
        if ".svn" in dirs:
            dirs.remove(".svn")
        if files != []:
            results.append((os.path.join(dest, root), [os.path.join(src, root, x) for x in files]))
    os.chdir(cwd)

doc_and_conf_files = []
build_file_list(doc_and_conf_files, DOC_DIR, "config", src="src")
build_file_list(doc_and_conf_files, DOC_DIR, "report_template", src="src")
build_file_list(doc_and_conf_files, "/usr/local/share/locale/", ".", src="src/config/language")
doc_and_conf_files.append((DOC_DIR,
                           ["doc/AUTHORS",
                            "doc/ChangeLog_Wapiti",
                            "doc/ChangeLog_lswww",
                            "INSTALL",
                            "README",
                            "TODO",
                            "doc/example.txt"]))
doc_and_conf_files.append(("/usr/local/share/man/man1", ["doc/wapiti.1.gz"]))

# Main
setup(
    name="wapiti",
    version=VERSION,
    description="A web application vulnerability scanner",
    long_description="""\
Wapiti allows you to audit the security of your web applications.
It performs "black-box" scans, i.e. it does not study the source code of the
application but will scans the webpages of the deployed webapp, looking for
scripts and forms where it can inject data.
Once it gets this list, Wapiti acts like a fuzzer, injecting payloads to see
if a script is vulnerable.""",
    url="http://wapiti.sourceforge.net/",
    author="Nicolas Surribas",
    author_email="nicolad.surribas@gmail.com",
    license="GPLv2",
    platforms=["Any"],
    package_dir={"": "src"},
    packages=find_packages("src"),
    namespace_packages=['wapiti'],
    data_files=doc_and_conf_files,
    include_package_data=True,
    scripts=["src/wapiti.py"],
#    cmdclass={
#        "install_lib": wapiti_install_lib,
#        "install_scripts": wapiti_install_scripts
#    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Operating System :: Unix',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP :: Indexing/Search',
        'Topic :: Software Development :: Testing'
    ],
    install_requires=[
        'requests>=1.2.3',
        'BeautifulSoup'
    ]
)
