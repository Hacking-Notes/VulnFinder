import json
import subprocess

from modules.structure import Status


class WappalyzerScanner:
    def __init__(self, target):
        self.target = target
        self.whitelist = [1, 2, 3, 6, 7, 8, 9, 11, 14, 15, 16, 18, 19, 20, 21, 22, 24, 26, 27, 29, 30, 33, 34, 37, 39,
                          41, 45, 46, 47, 48, 50, 52, 53, 56, 57, 58, 60, 64, 65, 69, 74, 78, 80, 81, 82, 85, 86, 87,
                          97, 95, 103, 109]

        # Read Wappalyzer src/categories.json for whitelist references.

    def set_target(self, target):
        self.target = target

    def scan(self, extended, lazymode) -> [Status, str]:
        result = []

        command = "node api/wappalyzer/src/drivers/npm/cli.js " + self.target
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        out, err = proc.communicate()
        out = out.decode().strip().replace('null', '"?.?"')
        tech_list = json.loads(out)

        for tech in tech_list['technologies']:
            breakflag = False

            if not extended:  # Skip non-whitelisted technologies.
                breakflag = True
                for cat in tech['categories']:
                    if cat['id'] in self.whitelist:
                        breakflag = False
                        break

            if breakflag: continue

            if tech['version'] is None:
                version = "?.?"
            else:
                version = tech['version']

            if tech['version'] == "?.?" and lazymode:  # Do not append unknown versions if in lazy mode.
                continue
            result.append({'name': tech['name'], 'version': version, 'confidence': tech['confidence']})
        return [Status, result]
