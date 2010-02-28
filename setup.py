#!/usr/bin/python
from distutils.core import setup
from distutils.command.install_lib import install_lib
from distutils.command.install_scripts import install_scripts
import os

VERSION = "SVN"

class wapiti_install_lib(install_lib):
    def run(self):
        # Remove useless files
        os.remove(os.path.join(self.build_dir, 'wapiti', 'wapiti.py'))
        install_lib.run(self)


class wapiti_install_scripts(install_scripts):
    def run(self):
        install_scripts.run(self)
        # Rename wapiti.py to wapiti
        os.rename(os.path.join(self.install_dir, 'wapiti.py'), os.path.join(self.install_dir, 'wapiti'))


# Build file lists
def build_file_list(results, root, path):
    for file in os.listdir(os.path.join(root, path)):
        path_file = os.path.join(path, file)

        if os.path.isdir(os.path.join(root, path_file)):
            build_file_list(results, root, path_file)
        else:
            results.append(path_file)

list_package_data = []
build_file_list(list_package_data, "src", "config/language")
build_file_list(list_package_data, "src", "config/vulnerabilities")
build_file_list(list_package_data, "src", "report_template")

list_etc_wapiti_attacks = []
build_file_list(list_etc_wapiti_attacks, "", "src/config/attacks")


# Main
setup(
    name = "wapiti",
    version = VERSION,
    description = "A web application vulnerability scanner",
    long_description = """\
Wapiti allows you to audit the security of your web applications.
It performs "black-box" scans, i.e. it does not study the source code of the
application but will scans the webpages of the deployed webapp, looking for
scripts and forms where it can inject data.
Once it gets this list, Wapiti acts like a fuzzer, injecting payloads to see
if a script is vulnerable.""",
    url = "http://wapiti.sourceforge.net/",
    author = "Nicolas Surribas, David del Pozo, Alberto Pastor",
    license = "GPLv2",
    platforms = ["Linux"],
    package_dir = {"wapiti": "src"},
    packages = ["wapiti", 
                "wapiti.attack", 
                "wapiti.file", 
                "wapiti.language", 
                "wapiti.net", 
                "wapiti.net.httplib2", 
                "wapiti.report" 
    ],
    package_data = {
        'wapiti': list_package_data
    },
    data_files = [
        ("/etc/wapiti/attacks", list_etc_wapiti_attacks),
        ("share/man/man1", ["doc/wapiti.1.gz"]),
        ("share/doc/packages/wapiti-" + VERSION, ["AUTHORS", "ChangeLog_Wapiti", "ChangeLog_lswww", "README", "TODO", "example.txt"])
    ],
    scripts = ["src/wapiti.py"],
    cmdclass = {
        "install_lib"     : wapiti_install_lib,
        "install_scripts" : wapiti_install_scripts
    }
)
