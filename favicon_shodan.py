import mmh3, base64, sys
import requests, argparse, socket
from urllib.parse import urlparse
from requests.exceptions import RequestException
import urllib3

urllib3.disable_warnings()

parser = argparse.ArgumentParser(description="Search for a target by favicon")
parser.add_argument("-u","--url", help="For a target URL. (Exemple: https://www.hackerone.com/favicon.ico)")
args = parser.parse_args()

URL = args.url

if args.url == None:
    print("[-] URL target is missing, try using -u <url> or --url <url>")
    sys.exit()
else:
    domain = urlparse(URL).netloc
    print(f"\n\033[94m\n[+] Target ===> {domain}\n")

try:
    req = requests.get(URL, verify=False)
    resp = req.content
    resp_encoded = base64.encodebytes(resp)
    if req.status_code == 200:
        hash_favicon = str(mmh3.hash(resp_encoded))
        query = f"{requests.utils.quote(f'http.favicon.hash:{hash_favicon}')}" + "+" + f"{requests.utils.quote(f'ip:{socket.gethostbyname(domain)}')}"
        print(f'\033[92m\t-> http.favicon.hash:{hash_favicon}')
        print(f"\033[92m\t-> Search in Shodan ===> https://www.shodan.io/search?query={query}\n")
        print(f"\n\033[93m[!] Go to https://www.shodan.io/search?query/search?query={requests.utils.quote(f'http.favicon.hash:{hash_favicon}')}\nto try get other targets with the same favicon!\n")
    else:
        pass
except (RequestException, socket.gaierror) as err:
    print(f"[-] One Error occurred: {err}")
