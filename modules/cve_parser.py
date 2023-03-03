import requests

from modules.printer import Printer
from modules.structure import Vulnerability, Status, Technology, PoC


class CVEParser:
    def __init__(self, cvefilter: int, cpefilter: int, printer: Printer, nvd_token: str):
        self.printer = printer
        self.api = "nvd"
        self.__api_key_header = {"apiKey": nvd_token}  # Should be changed to corporative.
        self.cve_filter = cvefilter
        self.cpe_filter = cpefilter
        self.cpe_api_link = "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch="  # CPE NVD search api.
        self.cve_api_link = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName="  # CVE NVD search api.

    def cpe_list_analyze(self, tech: Technology, lazymode: bool, status, cpe_list: list) -> [Status, Technology]:

        # Tries to get CPE using Technology name.

        if not status:  # If CPE lookup completely failed.
            return status, tech

        if len(cpe_list) > 1 and not lazymode:  # If multiple CPE's found user should choose which one to use.
            self.printer.print(f"[-] Several products found for {tech.name}. Please, select which one is correct:")
            count = 0
            for cpe in cpe_list:
                self.printer.print(f"{count + 1}: {cpe[0]}")
                count += 1
            original_cpe_list = cpe_list
            while True:

                try:
                    selector = int(input(f"\nSpecify version of {tech.name} or use 0 to apply filter: "))
                except:  # TODO: correct exception
                    self.printer.print("[!] Wrong number!")
                    continue

                # "selector-1" used for human-readable list and for "0" usage for filtering.

                if 0 <= selector - 1 < len(cpe_list):  # If number from CPE list selected, proceeding with it.
                    tech.cpe_name, tech.cpe_ID = cpe_list[selector - 1]
                    tech.version = cpe_list[selector - 1][0].split(":")[5]  # Update Technology version based on chosen.
                    break

                elif selector == 0:  # Recursive list filtering.
                    results_filter = input("Specify substring to filter or enter 'restore' "
                                           "to restore original list: ")
                    if results_filter == "restore":  # Restore original list.
                        cpe_list = original_cpe_list
                        count = 0
                        for cpe in cpe_list:
                            self.printer.print(f"{count + 1}: {cpe[0]}")
                            count += 1
                        continue
                    updated_cve = []
                    counter = 0
                    for cpe in cpe_list:
                        if results_filter in cpe[0]:
                            print(f"{counter + 1}: {cpe[0]}")
                            counter += 1
                            updated_cve.append(cpe)
                    cpe_list = updated_cve

                elif selector == 13371337:  # Debug feature
                    exit()

                elif selector == 10002:  # Debug feature
                    return Status(status=False, message=f"[-] Skipped."), tech

                else:  # Number exceeds length of CPE list.
                    self.printer.print("[!] Incorrect number!")
        elif len(cpe_list) > 1 and lazymode:
            return Status(status=False, message=f"[-] Skipped {tech.name} due to laziness."), tech
        else:
            tech.cpe_name, tech.cpe_ID = cpe_list[0]
        self.printer.print(f"[+] Working with {tech.cpe_name}, ID {tech.cpe_ID}")

        return status, tech

    def get_all_cves_for_product(self, tech: Technology) -> [Status, Technology]:

        # Tries to get all CVE's linked to forwarded CPE.
        cpe_name = tech.cpe_name
        results = []
        r = requests.get(self.cve_api_link + cpe_name, headers=self.__api_key_header)
        cves = r.json()['vulnerabilities']

        if not cves:  # If empty list returned (No CVE's for forwarded CPE)
            return Status(status=False, message=f"[-] No CVE's found for {cpe_name}."), tech

        for cve in cves:
            if int(cve['cve']['id'].split("-")[1]) < self.cve_filter:  # Grab year from CVE id and compare to filter.
                continue

            link_list = []
            for link in cve['cve']['references']:  # Grab all links with "Exploit" tag from NVD page.
                if 'tags' not in link:
                    continue
                if "Exploit" in link['tags']:
                    link_list.append(PoC(parent_name=cve['cve']['id'], link=link['url'], source="NVD",
                                         title="NVD Exploit Reference"))

            # Get CVSS score (not "basicScore", but "impactScore")
            if 'cvssMetricV31' in cve['cve']['metrics']:
                score = cve['cve']['metrics']['cvssMetricV31'][0]['impactScore']
            elif "cvssMetricV2" in cve['cve']['metrics']:
                score = cve['cve']['metrics']['cvssMetricV2'][0]['impactScore']
            else:
                score = 0

            # Cast found information to Vulnerability object and put it into resulting list.

            results.append(Vulnerability(name=cve['cve']['id'], severity=score,
                                         description=cve['cve']['descriptions'][0]['value'], pocs=link_list))

        tech.vulns = results
        return Status(), tech

    def get_all_cpes_for_product(self, tech: Technology, lazymode: bool, flag=False) -> [Status, list, Technology]:

        # Tries to get app CPE's based on product name and version.

        self.printer.print(f"[~] Getting CPE of {tech.name}...")

        if flag:
            version = "?.?"
        else:
            version = tech.version
        product = tech.name
        results = []

        if version == "?.?" and lazymode:
            return Status(), ["Lazy", "skip"], tech
        elif version == "?.?":
            r = requests.get(self.cpe_api_link + product, headers=self.__api_key_header)
        else:
            r = requests.get(self.cpe_api_link + product + " " + version, headers=self.__api_key_header)
        products = r.json()['products']

        for prod in products:  # Filter CPE based on cpe_filter year.
            if int(prod['cpe']['created'].split('-')[0]) >= self.cpe_filter:
                results.append([prod['cpe']['cpeName'], prod['cpe']['cpeNameId']])

        if not results and version != "?.?" and not lazymode:

            # If no CPE's found for specific version, we assume that it's formatting
            # is incorrect and try to recursively find all versions of Technology.

            self.printer.print(f"[~] No CPE's found for {product} {version}, trying to get all versions...")
            status, results, tech = self.get_all_cpes_for_product(tech, lazymode, flag=True)
            return status, results, tech

        elif not results:
            # Finally, if wildcard version is used and nothing found - abaddon that Technology.
            return Status(status=False, message=f"[!] No products (CPEs) found for {product} {version}."), results, tech

        else:
            # Results found, return resulting list.
            return Status(), results, tech
