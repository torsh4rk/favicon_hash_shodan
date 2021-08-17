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


usage: favicon_shodan.py [-h] [-u URL]

Search for a target by favicon

optional arguments:
  -h, --help         show this help message and exit
  -u URL, --url URL  For a target URL. (Exemple: https://www.hackerone.com/favicon.ico)

```

## RUN

```
favicon_hash_shodan: python3 favicon_shodan.py --url=https://www.hackerone.com/favicon.ico

[+] Favicon Domain Target ===> www.hackerone.com
[+] View Results for Target www.hackerone.com (http.favicon.hash:595148549):

	-> Search in Shodan (Link 1) ===> https://www.shodan.io/search?query=http.favicon.hash%3A595148549 (Dork: http.favicon.hash:595148549)
	-> Search in Shodan (Link 2) ===> https://www.shodan.io/search?query=http.favicon.hash%3A595148549+org%3Awww.hackerone.com (Dork: http.favicon.hash:595148549 + org:www.hackerone.com)
	-> Search in Shodan (Link 3) ===> https://www.shodan.io/search?query=http.favicon.hash%3A595148549+ip%3A104.16.99.52 (Dork: http.favicon.hash:595148549 + ip:104.16.100.52)



```

## References

```
-> https://isc.sans.edu/forums/diary/Hunting+phishing+websites+with+favicon+hashes/27326/
-> https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139
-> https://infosecwriteups.com/using-shodan-better-way-b40f330e45f6

```






