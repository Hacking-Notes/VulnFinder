# VulnFinder

VulnFinder is Python command-line tool that'll save ye time and effort by automatin' the process of detecting the technologies and versions used on a website using Wappalyzer. But that be not all, VulnFinder is also checkin' the infamous Exploit-DB for any known vulnerabilities associated with the detected technologies.

With VulnFinder in yer arsenal, you won't have to waste time manually checking for CVE's and corresponding proof-of-concepts. It'll do all the heavy liftin' for you, allowing you to focus on more important things!

## Installation
There are few steps to prepare VulnFinder.
1. Install Wappalyzer dependencies: [Git](https://git-scm.com/), 
[Node.js 14+](https://nodejs.org/), [Yarn](https://yarnpkg.com/).  

2. Clone VulnFinder repository:
```
git clone https://github.com/Hacking-Notes/VulnFinder
```

3. Prepare Wappalyzer:
```
cd VulnFinder/api/wappalyzer
yarn install
yarn run link
```

4. Install dependencies:

```
cd ../../
pip3 install -r requrements.txt
```

5. Edit _tokens.json_ file, add your [GitHub](https://github.com/settings/tokens/) 
and [NVD](https://nvd.nist.gov/developers/api-key-requested) tokens here.
6. Run VulnFinderr:
```
python3 VulnFinder.py [arguments] <url/host>
```
## Credit

- <a href="https://github.com/SpiritOfSea/POCHunter">SpiritOfSea</a> ---> Original Creator

## Disclaimer

The tool provided on this GitHub page is intended for educational and research purposes only. The creators and maintainers of this tool are not responsible for any misuse or illegal use of the tool. It is the responsibility of the users to ensure that they comply with all applicable laws and regulations while using the tool.

---

  ![image](https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fwww.net-model.com%2Fimg%2Flogo-discord.png&f=1&nofb=1&ipt=0b347aa70a05f91f4015e7e1049581eba2f397f35b8f27ebb18ae2190210f8ea&ipo=images)ㅤContact Me: Discord --> LXC#3100
