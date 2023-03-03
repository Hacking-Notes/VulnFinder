#!/usr/bin/env python3

import argparse
import json
import os.path

from modules.host_handler import Host
from modules.printer import Printer
from modules.structure import Technology


class POCHunter:
    def __init__(self):
        self.host_manager = None
        self.loaded_flag = False
        self.header = """======================================================
 _____   ____   _____ _    _             _            
|  __ \ / __ \ / ____| |  | |           | |           
| |__) | |  | | |    | |__| |_   _ _ __ | |_ ___ _ __ 
|  ___/| |  | | |    |  __  | | | | '_ \| __/ _ \ '__|
| |    | |__| | |____| |  | | |_| | | | | ||  __/ |   
|_|     \____/ \_____|_|  |_|\__,_|_| |_|\__\___|_|                                                
======================================================="""
        self.version_info = """Author: Dzmitry Padabed\n\nPOCHunter is a tool to automate website scanning, finding \
corresponding web technologies versions and their vulnerabilities. Searches are made with the power of Wappy, \
NVD and exploitDB."""

        self.init_parser()
        self.printer = Printer(self.args.nocolor)
        self.init_host_manager()

    def run(self):

        if not self.args.format == "json":
            print(self.header)

        # Runtime route is chosen by used flags. Default one completes all scans.
        if self.args.debug:
            pass
        elif self.args.version:
            self.version()
        elif self.args.check:
            self.check()
        elif self.args.vulns:
            self.list_vulns()
        elif self.args.techs:
            self.techs()
        else:
            self.default()

    def init_parser(self):
        self.parser = argparse.ArgumentParser(prog="./POCHunter.py", description="Tool to automatically find web "
                                                                                 "exploits' proofs of concept")
        self.parser.add_argument("hostname")
        self.parser.add_argument('-f', '--force', help="ignore cached results", action='store_true')
        self.parser.add_argument('-l', '--lazy', help="skip unknown versions", action="store_true")
        self.parser.add_argument('-t', '--techs', help="perform only web technologies detect", action='store_true')
        self.parser.add_argument('--check', help="check if host was cached before", action="store_true")
        self.parser.add_argument('--vulns', help="list all CVE's for cached site", action="store_true")
        self.parser.add_argument('--version', help="display author and version info", action="store_true")
        self.parser.add_argument('--debug', action="store_true")
        self.parser.add_argument('-e', '--extended', help="disable technologies whitelisting", action="store_true")
        self.parser.add_argument('-c', '--cvedetails', help="show CVE descriptions", action='store_true')
        self.parser.add_argument('-hp', '--hidepocs', help="do not display PoC's", action='store_false')
        self.parser.add_argument('-of', '--format', help="choose output format: default, json", action='store')
        self.parser.add_argument('--nocolor', help="output without color", action="store_false")
        self.parser.add_argument('--cvefilter', help="set minimal year for CVEs (default: 2017)",
                                 default=2017, type=int)
        self.parser.add_argument('--cpefilter', help="set minimal year for CPEs (default: 2017)",
                                 default=2017, type=int)
        self.args = self.parser.parse_args()

    def debug(self):
        return 0

    def default(self):
        if not self.host_manager.has_technologies:
            self.host_manager.get_technologies(self.args.extended, self.args.lazy)
        if not self.args.format == "json":
            self.printer.print(self.host_manager.list_technologies()[1])
        if not self.host_manager.has_vulnerabilities:
            self.printer.print("[~] Searching for CPE's and CVE's...")
            self.host_manager.find_cpe_and_cve(self.args.lazy)
        if not self.host_manager.has_pocs:
            self.printer.print("[~] Looking for POC's...")
            self.host_manager.search_pocs()
            self.host_manager.save_results()

        self.printer.print(self.host_manager.list_all(show_cve=self.args.cvedetails, show_pocs=self.args.hidepocs,
                                                      output_format=self.args.format)[1].rstrip())

    def techs(self):  # Only scan techs.
        self.host_manager.get_technologies(self.args.extended)
        self.printer.print(self.host_manager.list_technologies()[1])

    def version(self):
        self.printer.print(self.version_info)

    def list_vulns(self):  # List cached vulnerabilities.
        if self.host_manager.has_vulnerabilities:
            self.printer.print(self.host_manager.list_vulnerabilities()[1])
        else:
            self.printer.print("[!] No vulnerabilities were found or host have never been scanned.")

    def init_host_manager(self):  # Host handler initialization.
        if os.path.exists("tokens.json"):  # Token loading.
            with open("tokens.json", "r") as file:
                tokens = json.loads(file.read())
        else:
            self.printer.print("[!] No 'tokens.json' found. Cannot load API keys. Aborting.")
            exit()

        # Search for cached host info in "./known-sites".

        if "://" in self.args.hostname:
            filename = self.args.hostname.split("://")[1]
        else:
            filename = self.args.hostname

        if os.path.exists("known-sites/" + filename) and not self.args.force:
            with open("known-sites/" + filename, "r") as file:
                self.host_manager = Host(hostname=self.args.hostname, cve_filter=self.args.cvefilter,
                                         cpe_filter=self.args.cpefilter, printer=self.printer,
                                         nvd_token=tokens["nvd_token"], github_token=tokens["github_token"])
                technologies = file.read().split("!|!")
                for tech in technologies:
                    if tech == "":
                        continue
                    self.host_manager.technologies.append(Technology.from_json(tech))
            self.loaded_flag = True
            self.host_manager.check_content()

        # Default host initialization.

        else:
            self.host_manager = Host(hostname=self.args.hostname, cve_filter=self.args.cvefilter,
                                     cpe_filter=self.args.cpefilter, printer=self.printer,
                                     nvd_token=tokens["nvd_token"], github_token=tokens["github_token"])
            self.loaded_flag = False

    def check(self):  # Check if host was cached.
        if self.loaded_flag:
            self.printer.print(f"""[+] Host was already cached. Technologies: {self.host_manager.has_technologies}. 
                             Vulnerabilities: {self.host_manager.has_vulnerabilities}.
                             Proofs of Concept: {self.host_manager.has_pocs}""")
        else:
            self.printer.print(f"[-] There is no such host in database.")


if __name__ == "__main__":
    POCHunter = POCHunter()
    POCHunter.run()
