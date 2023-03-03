import operator
from concurrent.futures import ThreadPoolExecutor
from functools import partial

import simplejson

from modules.cve_parser import CVEParser
from modules.poc_parser import PocParser
from modules.printer import Printer
from modules.structure import Technology, Status
from modules.wappalyzer_api import WappalyzerScanner


# TODO: Integrate with NVD analogs?
# TODO: Optimization - multithreading?, request lightweighting
# TODO: DB integration??
# TODO: CPE selection better filtering?
# TODO: EDb search by title
# TODO: Associations file ("1C-Bitrix"->"bitrix")


class Host:

    def __init__(self, hostname: str, cve_filter: int, cpe_filter: int, printer: Printer,
                 github_token: str, nvd_token: str):

        self.printer = printer
        self.has_technologies = False
        self.has_pocs = False
        self.has_vulnerabilities = False

        # Check if address provided in "hostname.com", "https://hostname.com" or "http://hostname.com" format

        if "://" in hostname:
            self.protocol = hostname.split("://")[0] + "://"
            self.host = hostname[len(self.protocol):]
        else:
            self.protocol = "https://"
            self.host = hostname

        self.url = self.protocol + self.host
        self.technologies = []
        self.vulnerabilities = []
        self.wappy_scanner = WappalyzerScanner(self.protocol + self.host)
        self.cve_parser = CVEParser(cvefilter=cve_filter, cpefilter=cpe_filter,
                                    printer=self.printer, nvd_token=nvd_token)
        self.poc_parser = PocParser(printer=self.printer, github_token=github_token)

    def find_cpe_and_cve(self, lazymode: bool) -> [Status]:
        time_list = []
        pre_scan_batch = []

        # Threaded requests to NVD for initial CPE detection.

        with ThreadPoolExecutor(16) as executor:
            cpe_parser_part = partial(self.cve_parser.get_all_cpes_for_product, lazymode=lazymode)
            itera = executor.map(cpe_parser_part, self.technologies)
            for item in itera:
                status, cpe_list, tech = item
                pre_scan_batch.append([tech, status, cpe_list])

        # Analyze cpe_list, find correct CPE's.

        for item in pre_scan_batch:
            status, updated_tech = self.cve_parser.cpe_list_analyze(item[0], lazymode, item[1], item[2])

            if not status:
                self.printer.print(status)
            else:
                time_list.append(updated_tech)

        self.technologies = time_list
        self.printer.print("[~] Looking for CVE's...")

        # Threaded requests to NVD for CVE's.

        time_list = []
        with ThreadPoolExecutor(16) as executor:
            itera = executor.map(self.cve_parser.get_all_cves_for_product, self.technologies)
            for item in itera:
                status, tech = item
                if not status:  # If no CVE found
                    self.printer.print(status)

                time_list.append(tech)

        self.technologies = time_list
        return [Status()]

    def search_pocs(self) -> [Status]:

        # Send every Vulnerability in every Technology to poc_parser, replace it by returned one

        for tech in self.technologies:
            vuln_time_list = []

            with ThreadPoolExecutor(8) as executor:
                itera = executor.map(self.poc_parser.get_pocs, tech.vulns)
                for item in itera:
                    vuln_time_list.append(item[1])

            self.technologies[self.technologies.index(tech)].vulns = vuln_time_list

        return [Status()]

    def get_technologies(self, extended, lazymode) -> [Status]:

        # Get Technologies. If Wappalizer returned "unknown version", put "?.?" as version.

        tech_list = self.wappy_scanner.scan(extended, lazymode)[1]
        for tech in tech_list:
            self.technologies.append(Technology(name=tech['name'], version=tech['version'],
                                                confidence=tech['confidence']))
        return [Status]

    def list_technologies(self) -> [Status, str]:

        # Return string containing all detected technologies, sorted by Wappy confidence.

        result = ""
        for tech in sorted(self.technologies, key=operator.attrgetter("confidence"), reverse=True):
            result += "\n" + tech.name + " " + tech.version + ", confidence: " + str(tech.confidence)
        result += "\n"
        return [Status(), result]

    def list_vulnerabilities(self) -> [Status, str]:

        # Return string containing all vulnerabilities, sorted by Technology confidence and Vulnerability severity.

        result = ""
        for tech in sorted(self.technologies, key=operator.attrgetter("confidence"), reverse=True):
            if len(tech.vulns) == 0:
                continue
            result += f"\n===========================================\n||{' ' * int((20 - len(tech.name) / 2))}" \
                      f"{tech.name}{' ' * int((20 - len(tech.name) / 2))}||\n==========================================="
            for vuln in sorted(self.technologies[self.technologies.index(tech)].vulns,
                               key=operator.attrgetter("severity"), reverse=True):
                result += f"\n- {vuln.name}"
        return [Status(), result]

    def list_pocs(self) -> [Status, str]:

        # Return string containing all Proofs of Concept, grouped by Technologies and Vulnerabilities.
        # Returns PoC's from Vulnerability list (grabbed from ExploitDB) and links from CVE pages, containing
        # "Exploit" tag.

        result = ""

        for tech in sorted(self.technologies, key=operator.attrgetter("confidence"), reverse=True):
            result += f"\n===========================================\n||{' ' * int((20 - len(tech.name) / 2))}" \
                      f"{tech.name}{' ' * int((20 - len(tech.name) / 2))}||\n" \
                      f"==========================================="

            for vuln in sorted(self.technologies[self.technologies.index(tech)].vulns,
                               key=operator.attrgetter("severity"), reverse=True):
                result += f"\n=============={vuln.name}==============\n"

                for poc in self.technologies[self.technologies.index(tech)].vulns[tech.vulns.index(vuln)].pocs:
                    result += f"\n{poc.source}: {poc.title}\n{poc.link}\n\n"

        return [Status(), result]

    def list_all(self, show_cve=False, output_format="default", show_pocs=True) -> [Status, str]:

        # United method, which returns string containing Technologies, Vulnerabilities and PoC's.
        # "show_cve" - allows to print CVE descriptions, even if no PoC's found.
        # "output_format" - not used now, should choose from default(stdout)/json output format.
        # "show_pocs" - allows to hide links to exploits.

        result = ""

        if output_format == "json":
            for tech in self.technologies:
                result += simplejson.dumps(simplejson.loads(tech.to_json()), indent=4) + '\n'

        else:
            for tech in sorted(self.technologies, key=operator.attrgetter("confidence"), reverse=True):

                # Just Technology name with some pretty padding.

                result += f"\n===========================================\n||{' ' * int((20 - len(tech.name) / 2))}" \
                          f"{tech.name}{' ' * int((20 - len(tech.name) / 2))}||\n" \
                          f"==========================================="

                for vuln in sorted(self.technologies[self.technologies.index(tech)].vulns,
                                   key=operator.attrgetter("severity"), reverse=True):
                    header_marker = False  # Marker for CVE header deduplication.

                    if vuln.pocs and show_pocs:

                        if not header_marker:
                            result += f"\n\n=============={vuln.name}=============="

                            if show_cve:
                                result += f"\n\nCVSS Score: {vuln.severity}"
                                result += f"\nDescription: {vuln.description}"
                            header_marker = True

                        for poc in self.technologies[self.technologies.index(tech)].vulns[tech.vulns.index(vuln)].pocs:
                            result += f"\n\n{poc.source}: {poc.title}\n{poc.link}\n"

                    if not header_marker and show_cve:
                        result += f"\n\n=============={vuln.name}=============="
                        result += f"\n\nCVSS Score: {vuln.severity}"
                        result += f"\nDescription: {vuln.description}"

        return [Status(), result]

    def save_results(self) -> [Status]:

        # Dumps scan results into json file.

        res = ""
        for tech in self.technologies:
            res += simplejson.dumps(simplejson.loads(tech.to_json()), indent=4) + "!|!"

        try:
            with open("known-sites/" + self.host, 'w') as file:
                file.write(res)
            return Status()

        except Exception as e:
            return Status(status=False, message=f"Error while saving to file: {str(e)}")

    def check_content(self):

        # Detect what parts of scan process are cached.

        self.has_technologies = False
        self.has_vulnerabilities = False
        self.has_pocs = False

        if self.technologies:
            self.has_technologies = True

        else:
            return

        for tech in self.technologies:
            if tech.vulns:
                self.has_vulnerabilities = True
                break

        if not self.has_vulnerabilities:
            return

        for tech in self.technologies:
            for vuln in tech.vulns:
                if vuln.pocs:
                    self.has_pocs = True
                    break
        return
