import os
import dnstwist
import requests
from PIL import Image
from imagehash import phash
import time
import pandas as pd
import csv
from colorama import Fore, Style, init
import argparse
from dotenv import load_dotenv


init(autoreset=True)# Initialize colorama
load_dotenv()  # Load environment variables from .env file

# Parse command-line arguments
parser = argparse.ArgumentParser(description="TwistScan (dnstwist + urlscan.io) -- This app combines the power of DNSTwist (https://github.com/elceef/dnstwist/tree/master) and URLScan (https://urlscan.io/) to analyze domains. -- Remember to set the API key (URLSCAN_API) in .env file")
parser.add_argument("--domain", required=True, help="Original domain to analyze")
parser.add_argument("--output-dnstwist", default="output_dnstwist.csv", help="Output file for DNSTwist results (default: output_dnstwist.csv)")
parser.add_argument("--output-urlscan", default="output_urlscan.csv", help="Output file for URLScan results (default: output_urlscan.csv)")
parser.add_argument("--screenshot-folder", default="screenshots", help="Folder to save screenshots (default: screenshots)")
args = parser.parse_args()

# Assign arguments to variables
ORIGINAL_DOMAIN = args.domain

API_KEY = os.getenv("URLSCAN_API")
if not API_KEY:
    raise ValueError("API key not found. Please set it in the .env file.")
OUTPUT_FILE = args.output_dnstwist
OUTPUT_FILE_URLSCAN = args.output_urlscan
SCREENSHOT_FOLDER = args.screenshot_folder
URLSCAN_API = 'https://urlscan.io/api/v1/scan/'
URLSCAN_RESULT = 'https://urlscan.io/api/v1/result/'
MAX_WAIT_TIME = 300  # Maximum wait time in seconds
POLL_INTERVAL = 5  # Polling interval in seconds

# Ensure the screenshot folder exists
if os.path.exists(SCREENSHOT_FOLDER):
    for file in os.listdir(SCREENSHOT_FOLDER):
        file_path = os.path.join(SCREENSHOT_FOLDER, file)
        if os.path.isfile(file_path):
            os.remove(file_path)
else:
    os.makedirs(SCREENSHOT_FOLDER, exist_ok=True)

# Check if the output files exist and delete them
for output_file in [OUTPUT_FILE, OUTPUT_FILE_URLSCAN]:
    if os.path.exists(output_file):
        os.remove(output_file)

# Run dnstwist
print(f"{Fore.CYAN}Running DNSTwist...")
dnstwist.run(
    domain=ORIGINAL_DOMAIN,
    registered=True,
    format='csv',
    output=OUTPUT_FILE,
    nameservers="8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1",
    tld="tld-list.dict",
	dictionary="dictionary-dnstwist.dict",
    fuzzers="*original,addition,bitsquatting,cyrillic,homoglyph,hyphenation,insertion,omission,plural,repetition,replacement,subdomain,transposition,various,vowel-swap,tld-swap,dictionary"
)

# Check if the output file exists
if os.path.exists(OUTPUT_FILE):
    data = pd.read_csv(OUTPUT_FILE)
    if not data.empty:
        domains = data['domain'].tolist()
        print(f"\n{Fore.CYAN}=== Domains Found ===")
        for domain in domains:
            print(f"{Fore.GREEN}- {domain}")
        print(f"{Fore.CYAN}=====================\n")

        # Prepare the URLScan CSV file
        fields = [
            'DNSTwist Domain', 'URLScan Domain', 'Report URL', 'ASN', 'ASN Name', 'IP', 'Country', 'Server', 'URL', 'Redirected',
            'MIME Type', 'Title', 'TLS Valid Days', 'TLS Age Days', 'TLS Valid From',
            'Apex Domain', 'TLS Issuer', 'Status', 'Links', 'Phash', 'Similarity'
        ]
        with open(OUTPUT_FILE_URLSCAN, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(fields)

        for domain in domains:
            print(f"\n{Fore.YELLOW}=== Processing Domain: {domain} ===")
            response = requests.post(
                URLSCAN_API,
                headers={'API-Key': API_KEY, 'Content-Type': 'application/json'},
                json={'url': f'http://{domain}', 'visibility': 'public'}
            )
            if response.status_code == 200:
                scan_id = response.json().get('uuid')
                print(f"Submitted {domain} to URLScan, scan ID: {scan_id}")

                result_url = f"{URLSCAN_RESULT}{scan_id}"
                print(f"Result URL (JSON): {result_url}")
                elapsed_time = 0
                time.sleep(10)  # Initial wait
                while elapsed_time < MAX_WAIT_TIME:
                    result_response = requests.get(result_url)
                    if result_response.status_code == 200:
                        result_data = result_response.json()
                        screenshot_url = result_data['task']['screenshotURL']
                        report_url = result_data['task']['reportURL']
                        print(f"Report URL: {report_url}")

                        data_row = [
                            domain,
                            result_data['page'].get('domain', 'N/A'),
                            report_url,
                            result_data['page'].get('asn', 'N/A'),
                            result_data['page'].get('asnname', 'N/A'),
                            result_data['page'].get('ip', 'N/A'),
                            result_data['page'].get('country', 'N/A'),
                            result_data['page'].get('server', 'N/A'),
                            result_data['page'].get('url', 'N/A'),
                            result_data['page'].get('redirected', 'N/A'),
                            result_data['page'].get('mimeType', 'N/A'),
                            result_data['page'].get('title', 'N/A'),
                            result_data['page'].get('tlsValidDays', 'N/A'),
                            result_data['page'].get('tlsAgeDays', 'N/A'),
                            result_data['page'].get('tlsValidFrom', 'N/A'),
                            result_data['page'].get('apexDomain', 'N/A'),
                            result_data['page'].get('tlsIssuer', 'N/A'),
                            result_data['page'].get('status', 'N/A'),
                            result_data['data'].get('links', [])
                        ]

                        if screenshot_url:
                            screenshot_response = requests.get(screenshot_url)
                            if screenshot_response.status_code == 200:
                                screenshot_path = os.path.join(SCREENSHOT_FOLDER, f"{domain}.png")
                                with open(screenshot_path, 'wb') as screenshot_file:
                                    screenshot_file.write(screenshot_response.content)
                                print(f"Saved screenshot for {domain} at {screenshot_path}")

                                screenshot_image = Image.open(screenshot_path)
                                screenshot_phash = phash(screenshot_image)
                                print(f"{Fore.CYAN}pHash for {domain}: {screenshot_phash}")
                                data_row.append(screenshot_phash)

                                original_screenshot_path = os.path.join(SCREENSHOT_FOLDER, f"{ORIGINAL_DOMAIN}.png")
                                if os.path.exists(original_screenshot_path):
                                    original_image = Image.open(original_screenshot_path)
                                    original_phash = phash(original_image)
                                    distance = screenshot_phash - original_phash
                                    similarity = (1 - distance / len(screenshot_phash.hash) ** 2) * 100
                                    print(f"{Fore.GREEN}Similarity with {ORIGINAL_DOMAIN}: {similarity:.2f}%")
                                    data_row.append(similarity)
                            else:
                                print(f"{Fore.RED}Failed to retrieve screenshot for {domain}.")
                        else:
                            print(f"{Fore.RED}Screenshot not found for {domain}.")
                        
                        with open(OUTPUT_FILE_URLSCAN, mode='a', newline='', encoding='utf-8') as file:
                            writer = csv.writer(file)
                            writer.writerow(data_row)
                        print(f"{Fore.GREEN}URLScan data for {domain} written to {OUTPUT_FILE_URLSCAN}.")
                        break
                    elif result_response.status_code == 404:
                        print(f"Scan for {domain} is still in progress. Waiting...")
                        time.sleep(POLL_INTERVAL)
                        elapsed_time += POLL_INTERVAL
                    else:
                        print(f"{Fore.RED}Failed to retrieve scan result for {domain}: {result_response.text}")
                        break
            elif response.status_code == 400:
                print(f"{Fore.RED}Bad Request while submitting {domain} to URLScan.")
            else:
                print(f"{Fore.RED}Failed to submit {domain} to URLScan: {response.text}")
            print(f"{Fore.YELLOW}=========================\n")
else:
    print(f"{Fore.RED}Output file {OUTPUT_FILE} not found.")