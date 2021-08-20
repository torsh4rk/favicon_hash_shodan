import mmh3, base64, sys, os
import requests, argparse, socket, shodan
from urllib.parse import urlparse
from requests.exceptions import RequestException
import urllib3

urllib3.disable_warnings()

shodan_cli_api_key = "" # YOUR API KEY


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

def print_shodan_links(URL, domain, VERBOSE):

    hash_favicon = calcule_favicon_hash(URL, domain)
    if hash_favicon != None:
        query_1 = f"{requests.utils.quote(f'http.favicon.hash:{hash_favicon}')}"
        query_2 = f"{requests.utils.quote(f'http.favicon.hash:{hash_favicon}')}" + "+" + f"{requests.utils.quote(f'ip:{socket.gethostbyname(domain)}')}"
        print(f"\033[93m[+] View Results for Target {domain} (http.favicon.hash:{hash_favicon}):\n")
        print(f'\033[92m-> Search in Shodan (Link 1) => https://www.shodan.io/search?query={query_1} (Dork: http.favicon.hash:{hash_favicon})')
        if VERBOSE == 1:
            os.system(f"shodan search http.favicon.hash:{hash_favicon} " + "--fields ip_str,port --separator \" \" | awk '{print $1\":\"$2}'")
        else:
            pass
        print(f'\033[92m-> Search in Shodan (Link 2) => https://www.shodan.io/search?query={query_2} (Dork: http.favicon.hash:{hash_favicon} + ip:{socket.gethostbyname(domain)})')
        if VERBOSE == 1:
            os.system(f"shodan search http.favicon.hash:{hash_favicon} + ip:{socket.gethostbyname(domain)} " + "--fields ip_str,port --separator \" \" | awk '{print $1\":\"$2}'")
        else:
            pass
        print("\033[93m\nFinished!\n")
    else:
        sys.exit(1)


def main():

    # Arguments

    parser = argparse.ArgumentParser(description="Search for a target by favicon")
    parser.add_argument("-u","--url", help="For a favicon URL. (Exemple: https://www.hackerone.com/favicon.ico)")
    parser.add_argument("-i","--input", help="For a favicon URL list.")
    parser.add_argument("-v","--verbose", type=int, choices=[0,1], default=0, help="Set a verbose value to use the shodan_cli (API KEY Required).")
    
    args = parser.parse_args()

    URL = args.url
    INPUT = args.input
    VERBOSE = args.verbose

    # Validating the URL argument (args.url) and INPUT argument (args.input)

    if args.url == None and args.input == None:
        print("[-] URL and Wordlist target is missing, type -h or --help for help usage")
        sys.exit()
    elif args.url != None and args.input == None:
        if os.path.basename(urlparse(URL).path) == None or os.path.basename(urlparse(URL).path) != "favicon.ico":
            print("[-] Path '/favicon.ico' is missing on URL, type -h or --help for help usage.")
            sys.exit()
        else:
            if shodan_cli_api_key != "":
                print('\n')
                os.system(f"shodan init {shodan_cli_api_key}")
            domain = urlparse(URL).netloc
            print(f'\n\033[93m[+] Favicon Domain Target ===> {domain}')
            print_shodan_links(URL, domain, VERBOSE)
    elif args.url == None and args.input != None:
        if shodan_cli_api_key != "":
            print('\n')
            os.system(f"shodan init {shodan_cli_api_key}")
        print(f'[\n\033[93m+] Favicon URL Target (Wordlist) ===> {INPUT}')
    else:
        print(f'[-] URL and Wordlist can not be used together.')

if __name__ == "__main__":
    main()