import mmh3, base64, sys, os, time, platform
import requests, argparse, socket
from urllib.parse import urlparse
from requests.exceptions import RequestException
import urllib3

urllib3.disable_warnings()

# shodan_cli_api_key and URL_LIST var can be also setted manually bellow.
shodan_cli_api_key = ""
URL_LIST = ""

# results
http_favicon_hash = ""

# Get the Operating system name to be printed in the banner
# The shodan commands results is going to filter in according to Operating system name
system_name = platform.system()

# Calculate and return the http favicon hash value
def calcule_http_favicon_hash(URL, domain):
    
    global http_favicon_hash
    
    try:
        req = requests.get(URL, verify=False)
        resp = req.content
        resp_encoded = base64.encodebytes(resp)
        if req.status_code == 200 or req.status_code == 301 or req.status_code == 302:
            http_favicon_hash = str(mmh3.hash(resp_encoded))
        elif req.status_code == 404 or http_favicon_hash == "":
            req = requests.get(f"https://favicon.splitbee.io/?url={domain}", verify=False)
            resp = req.content
            resp_encoded = base64.encodebytes(resp)
            http_favicon_hash = str(mmh3.hash(resp_encoded))
    except (RequestException) as err:
        http_favicon_hash = None
        print(f"\033[91m Connection Error. Please, verify the target favicon URL or your connection. More Error details: {err}\033[97m\n")
    
    return http_favicon_hash

def print_shodan_links(URL, domain, VERBOSE):

    http_favicon_hash = calcule_http_favicon_hash(URL, domain)
    
    if http_favicon_hash != None:
        
        query_1 = f"{requests.utils.quote(f'http.favicon.hash:{http_favicon_hash}')}"
        query_2 = f"{requests.utils.quote(f'http.favicon.hash:{http_favicon_hash}')}" + "+" + f"{requests.utils.quote(f'ip:{socket.gethostbyname(domain)}')}"
        query_3 = f"{requests.utils.quote(f'http.favicon.hash:{http_favicon_hash}')}" + "+" + f"{requests.utils.quote(f'hostname:{domain}')}"
        
        print(f"\033[93m [+] View Results for Target {domain} (http.favicon.hash:{http_favicon_hash}):\n")
        print(f'\033[92m-> Search on Shodan (Link 1) => https://www.shodan.io/search?query={query_1} (Dork: http.favicon.hash:{http_favicon_hash})')
        print(f'\033[92m-> Search on Shodan (Link 2) => https://www.shodan.io/search?query={query_2} (Dork: http.favicon.hash:{http_favicon_hash} + ip:{socket.gethostbyname(domain)})')
        print(f'\033[92m-> Search on Shodan (Link 3) => https://www.shodan.io/search?query={query_3} (Dork: http.favicon.hash:{http_favicon_hash} + hostname:{domain})')
        
        if VERBOSE:
            
            print("\n\033[96m Running \"shodan init\" to initialize the Shodan command-line with the provided API_KEY value...  \033[97m\n")
            os.system('shodan init ' + shodan_cli_api_key)
            time.sleep(1)
            
            print(f"\n\033[93m [+] Get all subdomains for target {domain}...\033[97m\n")
            
            # if system_name == "Linux", use the awk command filter to get only the IP and Port values
            if system_name == "Linux" or system_name == "Darwin":
                print(f"\n\033[93m [+] Get all subdomains for target {domain}...\033[97m\n")
                os.system(f"shodan search http.favicon.hash:{http_favicon_hash} " + "--fields ip_str,port --separator \" \" | awk '{print $1\":\"$2}'")
                os.system(f"shodan search http.favicon.hash:{http_favicon_hash} + ip:{socket.gethostbyname(domain)} " + "--fields ip_str,port --separator \" \" | awk '{print $1\":\"$2}'")
            
            elif system_name == "Windows":
                print(f"\n\033[93m [+] Get all subdomains for target {domain}...\033[97m\n")
                os.system(f"shodan search http.favicon.hash:{http_favicon_hash} " + "--fields ip_str,port --separator \" \"")
                os.system(f"shodan search http.favicon.hash:{http_favicon_hash} + ip:{socket.gethostbyname(domain)} " + "--fields ip_str,port --separator \" \" '")
            
            # os.system(f"shodan search http.favicon.hash:{http_favicon_hash} " + "--fields ip_str,port --separator \" \"")
            # os.system(f"shodan search http.favicon.hash:{http_favicon_hash} + ip:{socket.gethostbyname(domain)} " + "--fields ip_str,port --separator \" \" '")
            # os.system(f"shodan search http.favicon.hash:{http_favicon_hash} " + "--fields ip_str,port --separator \" \" | awk '{print $1\":\"$2}'")
            # os.system(f"shodan search http.favicon.hash:{http_favicon_hash} + ip:{socket.gethostbyname(domain)} " + "--fields ip_str,port --separator \" \" | awk '{print $1\":\"$2}'")
        else:
            pass
    else:
        # Verify if a URL_LIST has been setted
        # if a URL_LIST has been setted, the programm is going to continue executing in case of "Connection Error", else it exit
        if URL_LIST:
            print(f"\033[91m[-] Error to calculate the http_favicon_hash for target {domain}.\033[97m\n")
            pass
        else: 
            print(f"\033[91m[-] Error to calculate the http_favicon_hash for target {domain}.\033[97m\n")
            sys.exit(1)

def main():
    
    global URL_LIST
    global shodan_cli_api_key

    # Banner
    print("\n\033[95mFavicon Shodan Searcher - v1.1\033[97m")
    print("\033[95mCoded by: @torsh4rk\033[97m\n")
    
    # Arguments
    parser = argparse.ArgumentParser(description="Favicon Shodan Searcher - Search for target frameworks by favicon hash on Shodan.", usage="Example: python favicon_shodan.py -u https://www.hackerone.com -v -ak YOUR_API_KEY")
    parser.add_argument("-u","--url", help="For a target URL. (Exemple: https://www.hackerone.com)")
    parser.add_argument("-ul","--url-list", help="For an URL list file path. (It can not be used with the --url option above)")
    parser.add_argument("-ak","--api-key", help="Set an API_KEY value for Shodan CLI (Optional) with the verbose option (-v).")
    parser.add_argument("-v","--verbose", help="Set a verbose value to use the shodan_cli (Option --api-key=API_KEY is required).", action="store_true")
    
    
    args = parser.parse_args()

    URL = args.url
    URL_LIST = args.url_list
    VERBOSE = args.verbose
    API_KEY = args.api_key
    
    # Validating the Shodan API KEY at variable "shodan_cli_api_key", the VERBOSE argument (args.verbose)
    if VERBOSE and not API_KEY:
        if shodan_cli_api_key == "":
            parser.print_help()
            print("\n\033[91m [-] Shodan API KEY value is missing, set it manually or via -ak (--api-key) option. \033[97m\n")
            sys.exit()
    elif VERBOSE and API_KEY:
        shodan_cli_api_key = API_KEY
    else:
        pass
    

    # Validating the URL argument (args.url) and URL_LIST argument (args.url_list)

    if args.url == None and args.url_list == None:
        parser.print_help()
        print("\n\033[91m [-] URL and URL_LIST target is missing. \033[97m\n")
        sys.exit()
    elif args.url != None and args.url_list == None:
        if os.path.basename(urlparse(URL).path) == None or os.path.basename(urlparse(URL).path) != "favicon.ico":
            if URL.endswith("/"):
                URL=URL.rstrip("/")
            URL=URL+"/favicon.ico"
        else:
            pass
        
        domain = urlparse(URL).netloc
        if domain.startswith("www."):
            domain = domain[4:]
        else:
            pass
        
        print(f'\n\033[93m [+] Favicon Domain Target ===> {domain}\033[97m')
        print_shodan_links(URL, domain, VERBOSE)

    elif args.url == None and args.url_list != None:

        print(f'\n\033[93m [+] Favicon URL Target (URL_LIST) ===> {URL_LIST}\033[97m')
    
        with open(URL_LIST, 'r') as file:
            for line in file:
                URL = line.strip()
                if os.path.basename(urlparse(URL).path) == None or os.path.basename(urlparse(URL).path) != "favicon.ico":
                    if URL.endswith("/"):
                        URL=URL.rstrip("/")
                    URL=URL+"/favicon.ico"
                else:
                    pass
                domain = urlparse(URL).netloc
                print(f'\n\033[93m [+] Favicon Domain Target ===> {domain}')
                print_shodan_links(URL, domain, VERBOSE)
        
    else:
        parser.print_help()
        print(f'\033[91m [-] URL and URL_LIST values can not be used together.\033[97m\n')
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except(KeyboardInterrupt):
        print("\033[91m Keyboard Interrupt. Exiting...\033[97m\n")
        sys.exit(1) 
    
    print("\n\033[93m\nFinished!\n\033[97m\n")
