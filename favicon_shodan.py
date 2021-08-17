import mmh3, base64, sys, os
import requests, argparse, socket, shodan
from urllib.parse import urlparse
from requests.exceptions import RequestException
import urllib3

urllib3.disable_warnings()

def calcule_favicon_hash(URL, domain):

    try:
        req = requests.get(URL, verify=False)
        resp = req.content
        resp_encoded = base64.encodebytes(resp)
        if req.status_code == 200 or req.status_code == 301 or req.status_code == 302:
            hash_favicon = str(mmh3.hash(resp_encoded))
            return hash_favicon
        elif req.status_code == 404:
            print("Favicon not found.")
            return None
    except (RequestException) as err:
        print("\033[91mConnection Error. \nPlease, verify the target favicon URL or your connection.")
        print(f"\033[91m\t-> More Error details: {err}\n")
        sys.exit(-1)
    except (KeyboardInterrupt):
        print('\033[91mCtrl + C typed. Exiting...\n')
        sys.exit(-1)

def print_shodan_links(URL, domain):

    hash_favicon = calcule_favicon_hash(URL, domain)
    if hash_favicon != None:
        query_1 = f"{requests.utils.quote(f'http.favicon.hash:{hash_favicon}')}"
        query_2 = f"{requests.utils.quote(f'http.favicon.hash:{hash_favicon}')}" + "+" + f"{requests.utils.quote(f'org:{domain}')}"
        query_3 = f"{requests.utils.quote(f'http.favicon.hash:{hash_favicon}')}" + "+" + f"{requests.utils.quote(f'ip:{socket.gethostbyname(domain)}')}"
        print(f"\033[93m[+] View Results for Target {domain} (http.favicon.hash:{hash_favicon}):\n")
        print(f'\033[92m\t-> Search in Shodan (Link 1) ===> https://www.shodan.io/search?query={query_1} (Dork: http.favicon.hash:{hash_favicon})')
        print(f'\033[92m\t-> Search in Shodan (Link 2) ===> https://www.shodan.io/search?query={query_2} (Dork: http.favicon.hash:{hash_favicon} + org:{domain})')
        print(f'\033[92m\t-> Search in Shodan (Link 3) ===> https://www.shodan.io/search?query={query_3} (Dork: http.favicon.hash:{hash_favicon} + ip:{socket.gethostbyname(domain)})')
    else:
        sys.exit(1)


def main():

    # Arguments

    parser = argparse.ArgumentParser(description="Search for a target by favicon")
    parser.add_argument("-u","--url", help="For a favicon URL. (Exemple: https://www.hackerone.com/favicon.ico)")
    parser.add_argument("-i","--input", help="For a favicon URL list.")
    args = parser.parse_args()

    URL = args.url
    INPUT = args.input

    # Validating the URL argument (args.url) and INPUT argument (args.input)

    if args.url == None and args.input == None:
        print("[-] URL and Wordlist target is missing, type -h for help usage")
        sys.exit()
    elif args.url != None and args.input == None:
        if os.path.basename(urlparse(URL).path) == None or os.path.basename(urlparse(URL).path) != "favicon.ico":
            print("[-] Favicon name is missing or it's wrong! Type -h or help for help usage.")
            sys.exit()
        else:
            domain = urlparse(URL).netloc
            print(f'\n\033[93m[+] Favicon Domain Target ===> {domain}')
            print_shodan_links(URL, domain)
    elif args.url == None and args.input != None:
        print(f'[\n\033[93m+] Favicon URL Target (Wordlist) ===> {INPUT}')
    else:
        print(f'[-] URL and Wordlist can not be used together.')


    # Checking the error connections, KeyboardInterrupt and Generating the Shodan Links

if __name__ == "__main__":
    main()