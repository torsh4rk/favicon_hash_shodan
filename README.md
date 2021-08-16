# Search for a target by favicon filter

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

[+] Target ===> www.hackerone.com

-> http.favicon.hash:595148549
-> Search in Shodan ===> https://www.shodan.io/search?query=http.favicon.hash%3A595148549+ip%3A104.16.99.52


[!] Go to https://www.shodan.io/search?query/search?query=http.favicon.hash%3A595148549
to try get other targets with the same favicon!


```





