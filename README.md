# Search for target Frameworks on Shodan via favicon hash

```
Description: Calculate favicon hashes for Shodan from target Frameworks and get other target hosts

```

## Install

```
➜ git clone https://github.com/torsh4rk/favicon_hash_shodan.git
➜ cd favicon_hash_shodan
➜ pip3 install -r requirements.txt

```

## Help Usage

```
favicon_hash_shodan: python3 favicon_shodan.py -h

Favicon Shodan Searcher - v1.1
Coded by: @torsh4rk

usage: Example: python favicon_shodan.py -u https://www.hackerone.com -v -ak YOUR_API_KEY

Favicon Shodan Searcher - Search for target frameworks by favicon hash on Shodan.

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     For a target URL. (Exemple: https://www.hackerone.com)
  -ul URL_LIST, --url-list URL_LIST
                        For an URL list file path. (It can not be used with the --url option above)
  -ak API_KEY, --api-key API_KEY
                        Set an API_KEY value for Shodan CLI (Optional) with the verbose option (-v).
  -v, --verbose         Set a verbose value to use the shodan_cli (Option --api-key=API_KEY is required).

```

## RUN

```
python3 favicon_shodan.py -u https://www.hackerone.com/

Favicon Shodan Searcher - v1.1
Coded by: @torsh4rk


 [+] Favicon Domain Target ===> www.hackerone.com
 [+] View Results for Target www.hackerone.com (http.favicon.hash:595148549):

-> Search on Shodan (Link 1) => https://www.shodan.io/search?query=http.favicon.hash%3A595148549 (Dork: http.favicon.hash:595148549)
-> Search on Shodan (Link 2) => https://www.shodan.io/search?query=http.favicon.hash%3A595148549+ip%3A104.16.100.52 (Dork: http.favicon.hash:595148549 + ip:104.16.100.52)


Finished!
```

## References

<br>https://isc.sans.edu/forums/diary/Hunting+phishing+websites+with+favicon+hashes/27326/
<br>https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139
<br>https://infosecwriteups.com/using-shodan-better-way-b40f330e45f6








