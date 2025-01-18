#!/usr/bin/env python3

import requests                                                       import re
import argparse                                                       import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor                     from googlesearch import search
                                                                      # Vulnerability Checks (simple checks for SQLi, XSS, etc.)
def is_vulnerable(parameter):                                             """Check if the parameter might be vulnerable (basic checks)."""      sqli_keywords = ["' OR", '" OR', "UNION SELECT", "--", "DROP TABLE"]                                                                        xss_keywords = ["<script>", "alert(", "onerror=", "javascript:"]
                                                                          for keyword in sqli_keywords:
        if keyword in parameter:                                                  return "Potential SQL Injection"
    for keyword in xss_keywords:
        if keyword in parameter:
            return "Potential Cross-Site Scripting (XSS)"             
    return None                                                       
def fetch_urls(domain):
    """Fetch URLs from Wayback Machine & Google Dorking."""
    headers = {'User-Agent': 'Mozilla/5.0'}
    urls = set()

    # Fetch from Wayback Machine
    try:
        response = requests.get(f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original", headers=headers)
        if response.status_code == 200:
            urls.update(response.text.split("\n"))
    except Exception as e:
        print(f"[!] Wayback Machine error: {e}")

    # Google Dorking for finding indexed URLs
    try:
        print("[*] Performing Google Dorking...")
        query = f"site:{domain} inurl:? inurl=&"
        # Fix the 'num' argument issue by using 'num_results'
        for result in search(query, num_results=10, stop=10, pause=2):
            urls.add(result)
    except Exception as e:
        print(f"[!] Google Dorking error: {e}")

    return list(urls)

def extract_parameters(url, placeholder="FUZZ"):
    """Extract full URL with parameters."""
    parsed_url = urlparse(url)
    params = re.findall(r'([?&])([^=#]+)=([^&#]*)', url)  # Extract parameters with values

    if not params:
        return None  # Skip URLs without parameters

    formatted_url = f"https://{parsed_url.netloc}{parsed_url.path}?"
    formatted_url += "&".join([f"{p[1]}={placeholder}" for p in params])  # Replace values with FUZZ
    return formatted_url, params

def extract_from_urls(urls, check_vulnerabilities=False, placeholder="FUZZ"):
    """Use multithreading to extract full URLs with parameters and check vulnerabilities."""
    formatted_urls = set()
    vulnerable_params = set()

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(extract_parameters, urls, [placeholder]*len(urls))
        for result in results:
            # Ensure the result is not None
            if result:
                url, params = result
                formatted_urls.add(url)
                if check_vulnerabilities:
                    # Check each parameter for vulnerabilities
                    for param in params:
                        vulnerability = is_vulnerable(param[2])
                        if vulnerability:
                            vulnerable_params.add(f"{url} -> {param[1]}: {vulnerability}")

    return formatted_urls, vulnerable_params

def save_results(domain, urls, vulnerabilities=None):
    """Save extracted URLs and vulnerabilities to results/{domain}.txt."""
    output_dir = "results"
    os.makedirs(output_dir, exist_ok=True)  # Create results folder if not exists
    file_path = os.path.join(output_dir, f"{domain}.txt")

    with open(file_path, "w") as file:
        file.write("Extracted URLs:\n")
        file.write("\n".join(sorted(urls)))
        if vulnerabilities:
            file.write("\n\nVulnerabilities Found:\n")
            file.write("\n".join(sorted(vulnerabilities)))

    print(f"[+] Results saved in: {file_path}")

def main():
    parser = argparse.ArgumentParser(description="ParamSel - Extract Full URLs with Parameters and Vulnerabilities")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (example.com)")
    parser.add_argument("-V", "--vulnerabilities", action="store_true", help="Check for potential vulnerabilities in parameters.")
    parser.add_argument("-f", "--file", help="File containing a list of domains to scan.")
    parser.add_argument("-p", "--placeholder", default="FUZZ", help="Placeholder for URL parameter values (default: FUZZ).")
    args = parser.parse_args()

    if args.file:
        # If a file is provided, process each domain from the file
        with open(args.file, "r") as file:
            domains = file.readlines()
        for domain in domains:
            domain = domain.strip()
            print(f"[*] Fetching URLs for domain: {domain}")
            urls = fetch_urls(domain)
            if urls:
                print(f"[*] Found {len(urls)} URLs. Extracting full parameterized URLs using multithreading...")
                formatted_urls, vulnerabilities = extract_from_urls(urls, check_vulnerabilities=args.vulnerabilities, placeholder=args.placeholder)

                if formatted_urls:
                    # Commenting this part so that URLs are not printed in terminal
                    # print("[+] Extracted URLs:")
                    # for url in sorted(formatted_urls):
                    #     print(f" - {url}")

                    if args.vulnerabilities and vulnerabilities:
                        print("\n[+] Vulnerabilities Found:")
                        for vuln in sorted(vulnerabilities):
                            print(f" - {vuln}")

                    save_results(domain, formatted_urls, vulnerabilities)
                else:
                    print("[!] No parameterized URLs found.")
            else:
                print("[!] No URLs found.")
    else:
        # Process a single domain
        print(f"[*] Fetching URLs for domain: {args.domain}")
        urls = fetch_urls(args.domain)

        if urls:
            print(f"[*] Found {len(urls)} URLs. Extracting full parameterized URLs using multithreading...")
            formatted_urls, vulnerabilities = extract_from_urls(urls, check_vulnerabilities=args.vulnerabilities, placeholder=args.placeholder)

            if formatted_urls:
                # Commenting this part so that URLs are not printed in terminal
                # print("[+] Extracted URLs:")
                # for url in sorted(formatted_urls):
                #     print(f" - {url}")

                if args.vulnerabilities and vulnerabilities:
                    print("\n[+] Vulnerabilities Found:")
                    for vuln in sorted(vulnerabilities):
                        print(f" - {vuln}")

                save_results(args.domain, formatted_urls, vulnerabilities)
            else:
                print("[!] No parameterized URLs found.")
        else:
            print("[!] No URLs found.")

if __name__ == "__main__":
    main()
