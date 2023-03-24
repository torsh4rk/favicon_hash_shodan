import re
import mmh3, base64, sys, os, time, platform
import requests, argparse, socket
from urllib.parse import urlparse
from requests.exceptions import RequestException
import urllib3

urllib3.disable_warnings()

# shodan_cli_api_key and URL_LIST var can be also setted manually bellow.
shodan_cli_api_key = ""
URL_LIST = ""

# Get the Operating system name to be printed in the banner
# The shodan commands results is going to filter in according to Operating system name
system_name = platform.system()

# Calculate and return the http favicon hash value
def calcule_http_favicon_hash(URL):
    
    http_favicon_hash = ""
    
    try:
        req = requests.get(URL, verify=False)
        resp = req.content
        resp_encoded = base64.encodebytes(resp)
        if req.status_code == 200 or req.status_code == 301 or req.status_code == 302:
            http_favicon_hash = str(mmh3.hash(resp_encoded))
        elif req.status_code == 403 or req.status_code == 404:
            req = requests.get(f"https://favicon.splitbee.io/?url={urlparse(URL).netloc}", verify=False)
            resp = req.content
            resp_encoded = base64.encodebytes(resp)
            http_favicon_hash = str(mmh3.hash(resp_encoded))
    except RequestException:
        http_favicon_hash = None
        print(f"\n\033[91m Request Exception error. Please, verify the connection with the provided URL {URL}. \033[97m\n")
    
    return http_favicon_hash

def print_shodan_links(URL, VERBOSE):
    
    regex = re.compile(r"([a-zA-Z0-9-]+\.)+([a-zA-Z]{2,}$)")
    # Get the DNS from the URL
    DNS = urlparse(URL).netloc; domain = DNS[4:] if DNS.startswith("www.") else DNS
    
    print(f'\n\033[93m [+] Domain (target): {domain}\033[97m') if regex.match(domain) else (print(f"\n\033[91m [-] The DNS {DNS} is not valid. \033[97m\n"), sys.exit(1))
    
    http_favicon_hash = calcule_http_favicon_hash(URL)
    
    
    if http_favicon_hash != None and len(http_favicon_hash) != 0:
        
        print(f"\033[93m [+] http.favicon.hash: {http_favicon_hash}\033[97m")
        
        query_1 = f"{requests.utils.quote(f'http.favicon.hash:{http_favicon_hash}')}"
        query_2 = f"{requests.utils.quote(f'http.favicon.hash:{http_favicon_hash}')}" + "+" + f"{requests.utils.quote(f'ip:{socket.gethostbyname(DNS)}')}"
        query_3 = f"{requests.utils.quote(f'http.favicon.hash:{http_favicon_hash}')}" + "+" + f"{requests.utils.quote(f'hostname:{domain}')}"
        
        print(f"\033[93m [+] View results for the target {domain} (http.favicon.hash:{http_favicon_hash}):\n")
        print(f'\033[92m -> Search on Shodan (Link 1) => https://www.shodan.io/search?query={query_1} \033[91m ==> '  f'\033[97m(Dork: http.favicon.hash:{http_favicon_hash}) \033[97m')
        print(f'\033[92m -> Search on Shodan (Link 2) => https://www.shodan.io/search?query={query_2} \033[91m ==> '  f'\033[97m(Dork: http.favicon.hash:{http_favicon_hash} + ip:{socket.gethostbyname(DNS)})\033[97m')
        print(f'\033[92m -> Search on Shodan (Link 3) => https://www.shodan.io/search?query={query_3} \033[91m ==> '  f'\033[97m(Dork: http.favicon.hash:{http_favicon_hash} + hostname:{domain})\033[97m')
        
        if VERBOSE:
            
            print("\n\033[96m Running \"shodan init\" to initialize the Shodan command-line with the provided API_KEY value...  \033[97m\n")
            os.system('shodan init ' + shodan_cli_api_key)
            time.sleep(1)
            
            print(f"\n\033[93m [+] Get all subdomains for the target {domain}...\033[97m\n")
            
            # if system_name == "Linux", use the awk command filter to get only the IP and Port values
            if system_name == "Linux" or system_name == "Darwin":
                print(f"\n\033[93m [+] Get all subdomains for target {domain}...\033[97m\n")
                os.system(f"shodan search http.favicon.hash:{http_favicon_hash} " + "--fields ip_str,port --separator \" \" | awk '{print $1\":\"$2}'")
                os.system(f"shodan search http.favicon.hash:{http_favicon_hash} + ip:{socket.gethostbyname(DNS)} " + "--fields ip_str,port --separator \" \" | awk '{print $1\":\"$2}'")
            
            elif system_name == "Windows":
                print(f"\n\033[93m [+] Get all subdomains for target {domain}...\033[97m\n")
                os.system(f"shodan search http.favicon.hash:{http_favicon_hash} " + "--fields ip_str,port --separator \" \"")
                os.system(f"shodan search http.favicon.hash:{http_favicon_hash} + ip:{socket.gethostbyname(DNS)} " + "--fields ip_str,port --separator \" \" '")
            
            # os.system(f"shodan search http.favicon.hash:{http_favicon_hash} " + "--fields ip_str,port --separator \" \"")
            # os.system(f"shodan search http.favicon.hash:{http_favicon_hash} + ip:{socket.gethostbyname(DNS)} " + "--fields ip_str,port --separator \" \" '")
            # os.system(f"shodan search http.favicon.hash:{http_favicon_hash} " + "--fields ip_str,port --separator \" \" | awk '{print $1\":\"$2}'")
            # os.system(f"shodan search http.favicon.hash:{http_favicon_hash} + ip:{socket.gethostbyname(DNS)} " + "--fields ip_str,port --separator \" \" | awk '{print $1\":\"$2}'")
        else:
            pass
    else:
        # Verify if a URL_LIST has been setted
        # if a URL_LIST has been setted, the programm is going to continue executing in case of "Request Error"; else it exit
        if URL_LIST:
            print(f"\n\033[91m [-] Error to calculate the http_favicon_hash for target {domain}.\033[97m\n")
            pass
        else: 
            print(f"\n\033[91m [-] Error to calculate the http_favicon_hash for target {domain}.\033[97m\n")
            sys.exit(1)

def main():
    
    # Banner
    print("\n\033[95m  Favicon Shodan Searcher - v1.1\033[97m")
    print("\033[95m  Coded by: @torsh4rk\033[97m\n")
    
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
            print("\n\n\033[91m [-] Shodan API KEY value is missing, set it manually or via -ak (--api-key) option. \033[97m\n")
            sys.exit()
    elif VERBOSE and API_KEY:
        shodan_cli_api_key = API_KEY
    else:
        pass
    

    # Validating the URL argument (args.url) and URL_LIST argument (args.url_list)
    
    regex = re.compile(
        r"^https?://"  # Check if it begins with http:// or https://
        r"([a-zA-Z0-9-]+\.)+([a-zA-Z]{2,6})+(.*)"  # Check the domain
    )

    if args.url == None and args.url_list == None:
        parser.print_help()
        print("\n\n\033[91m [-] URL or URL_LIST target is missing. \033[97m\n")
        sys.exit()
    
    elif args.url != None and args.url_list == None:
        
        
        print(f'\n\033[93m [+] Favicon URL Target: {URL}') if regex.match(URL) else (print(f"\n\033[91m [-] The URL {URL} provided is not valid. \033[97m\n"), sys.exit(1))

        if os.path.basename(urlparse(URL).path) == None or os.path.basename(urlparse(URL).path) != "favicon.ico":
            if URL.endswith("/"):
                URL=URL.rstrip("/")
            URL=URL+"/favicon.ico"
        else:
            pass
        
        print_shodan_links(URL, VERBOSE)

    elif args.url == None and args.url_list != None:

        print(f'\n\033[93m [+] Favicon URL Target (URL_LIST): {URL_LIST}\033[97m') if os.path.exists(URL_LIST) else (print(f'\n\033[91m [-] The provided URL_LIST path {URL_LIST} does not exist.'), sys.exit(1))

        with open(URL_LIST, 'r') as file:
            for line in file:
                URL = line.strip()
                if os.path.basename(urlparse(URL).path) == None or os.path.basename(urlparse(URL).path) != "favicon.ico":
                    if URL.endswith("/"):
                        URL=URL.rstrip("/")
                    URL=URL+"/favicon.ico"
                else:
                    pass
    
                print_shodan_links(URL, VERBOSE)
        
    else:
        parser.print_help()
        print(f'\n\033[91m [-] URL and URL_LIST values can not be used together.\033[97m\n')
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except(KeyboardInterrupt):
        print("\033[91m Keyboard Interrupt. Exiting...\033[97m\n")
        sys.exit(1) 
    
    print("\n\033[93m\n Finished!\n\033[97m\n")
