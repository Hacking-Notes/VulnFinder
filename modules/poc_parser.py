import time

import requests

from modules.printer import Printer
from modules.structure import PoC, Vulnerability, Status


class PocParser:

    def __init__(self, printer: Printer, github_token: str):
        self.printer = printer
        self.exploit_url = "https://www.exploit-db.com/exploits/"  # Exploit page link
        self.search_edb_api = "https://www.exploit-db.com/search?start=0&length=120&cve="  # Search page API.
        self.search_github_api = "https://api.github.com/search/repositories?q="
        self.github_api_headers = {"Accept": "application/vnd.github+json",
                                   "Authorization": github_token,
                                   "X-GitHub-Api-Version": "2022-11-28"}
        self.poc_list = []

    def get_pocs(self, vuln: Vulnerability) -> [Status, Vulnerability]:

        # Method that reformats scan results into Vulnerability objects.

        results_edb = self.request_from_exploitdb(vuln.name)
        for result in results_edb:
            vuln.pocs.append(PoC(parent_name=vuln.name, source="exploitdb", link=result['link'], title=result['title']))

        results_github = self.request_from_github(vuln.name)
        for result in results_github:
            vuln.pocs.append(PoC(parent_name=vuln.name, source="github", link=result['link'], title=result['title']))

        return [Status(), vuln]

    def request_from_exploitdb(self, current_cve: str) -> list:

        # Requests EDb api with CVE ID (CVE-XXXX-XX without "CVE"), parses response JSON into list of dicts.
        # 'User-Agent' MUST BE CUSTOM, cuz EDb blocks default requests agent.

        results = []

        r = requests.get(self.search_edb_api + current_cve[4:], headers={'X-Requested-With': "XMLHttpRequest",
                                                                         'Accept': "application/json",
                                                                         'User-Agent':
                                                                         "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) "
                                                                         "Gecko/20100101 Firefox/102.0"})

        for elem in r.json()['data']:
            results.append({'title': elem['description'][1], 'link': self.exploit_url + elem['id']})

        return results

    def request_from_github(self, current_cve: str) -> list:
        results = []

        r = requests.get(self.search_github_api + current_cve, headers=self.github_api_headers)

        try:
            for elem in r.json()['items']:
                results.append({'title': elem['full_name'], 'link': elem['html_url']})

        except KeyError as e:
            self.printer.print(f"[!] API overload while fetching PoC's from Github. Sleeping for 30s...")
            time.sleep(30)
            results = self.request_from_github(current_cve)

        return results
