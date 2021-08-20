# Search for a target by favicon

## Install

```
➜ git clone https://github.com/torsh4rk/favicon_hash_shodan.git
➜ cd favicon_hash_shodan
➜ pip3 install -r requirements.txt

```

## Help Usage

```
favicon_hash_shodan: python3 favicon_shodan.py -h

usage: favicon_shodan.py [-h] [-u URL] [-i INPUT] [-v {0,1}]

Search for a target by favicon

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     For a favicon URL. (Exemple: https://www.hackerone.com/favicon.ico)
  -i INPUT, --input INPUT
                        For a favicon URL list.
  -v {0,1}, --verbose {0,1}
                        Set a verbose value to use the shodan_cli (API KEY Required).

```

## RUN

```
favicon_hash_shodan: python3 favicon_shodan.py --url=https://www.hackerone.com/favicon.ico

[+] Favicon Domain Target ===> www.hackerone.com
[+] View Results for Target www.hackerone.com (http.favicon.hash:595148549):

-> Search in Shodan (Link 1) => https://www.shodan.io/search?query=http.favicon.hash%3A595148549 (Dork: http.favicon.hash:595148549)
-> Search in Shodan (Link 2) => https://www.shodan.io/search?query=http.favicon.hash%3A595148549+ip%3A104.16.99.52 (Dork: http.favicon.hash:595148549 + ip:104.16.100.52)

Finished!
```

## References

<br>https://isc.sans.edu/forums/diary/Hunting+phishing+websites+with+favicon+hashes/27326/
<br>https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139
<br>https://infosecwriteups.com/using-shodan-better-way-b40f330e45f6








