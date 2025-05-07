import os
import dnstwist
import requests
from PIL import Image
from imagehash import phash
import time
import streamlit as st
import pandas as pd
import csv
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Constants
URLSCAN_API = 'https://urlscan.io/api/v1/scan/'
URLSCAN_RESULT = 'https://urlscan.io/api/v1/result/'
MAX_WAIT_TIME = 300  # Maximum wait time in seconds
POLL_INTERVAL = 5  # Polling interval in seconds

# Streamlit app
st.title("TwistScan - URLScan + DNSTwist")
st.markdown("This app combines the power of [DNSTwist](https://github.com/elceef/dnstwist/tree/master) and [URLScan](https://urlscan.io/) to analyze domains.")
st.sidebar.header("Configuration")

# Input fields
original_domain = st.sidebar.text_input("Original Domain", "inthecyber.com")
api_key = os.getenv("URLSCAN_API")  # Load API key from .env file
# Input fields with default values
output_file = st.sidebar.text_input("DNSTwist CSV Output File", value="output_dnstwist.csv")
output_file_urlscan = st.sidebar.text_input("URLScan CSV Output File", value="output_urlscan.csv")
screenshot_folder = st.sidebar.text_input("Screenshot Folder", value="screenshots")

# Disable the button if fields are empty
if not original_domain or not api_key or not output_file or not output_file_urlscan or not screenshot_folder:
    st.sidebar.warning("Some fields in the Configuration sidebar are missing. Please fill them and remember to follow the guidelines lol. Remember to set the API key (URLSCAN_API) in .env file.")
    run_scan = st.sidebar.button("Run Scan", disabled=True)
else:
    run_scan = st.sidebar.button("Run Scan")

if run_scan:
	# Ensure the screenshot folder exists
	if os.path.exists(screenshot_folder):
		for file in os.listdir(screenshot_folder):
			file_path = os.path.join(screenshot_folder, file)
			if os.path.isfile(file_path):
				os.remove(file_path)
	else:
		os.makedirs(screenshot_folder, exist_ok=True)

	# Check if the output files exist and delete them
	for out_file in [output_file, output_file_urlscan]:
		if os.path.exists(out_file):
			os.remove(out_file)

	placeholder = st.empty()
	placeholder.progress(0, "Running DNSTwist...")
	time.sleep(1)
	placeholder.progress(50, "Running DNSTwist...")
	dnstwist.run(
		domain=original_domain,
		registered=True,
		format='csv',
		output=output_file,
		nameservers="8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1",
		tld="tld-list.dict",
		dictionary="dictionary-dnstwist.dict",
		fuzzers="*original,addition,bitsquatting,cyrillic,homoglyph,hyphenation,insertion,omission,plural,repetition,replacement,subdomain,transposition,various,vowel-swap,tld-swap,dictionary"
	)
	time.sleep(1)
	placeholder.progress(100, "Running DNSTwist...")
	time.sleep(1)
	placeholder.empty()

	

	# Check if the output file exists
	if os.path.exists(output_file):
		# Read the CSV file into a DataFrame
		data = pd.read_csv(output_file)
		# Check if the DataFrame is not empty
		if not data.empty:
			st.dataframe(data, hide_index=True)
			domains = data['domain'].tolist()  # Extract the 'domain' column as a list
			st.subheader("Domains Found")
			for domain in domains:
				st.write(f"- {domain}")

			# Prepare the URLScan CSV file
			# Fields for urlscan csv file
			fields = [
    			'DNSTwist Domain', 'URLScan Domain', 'Report URL', 'ASN', 'ASN Name',  'IP', 'Country', 'Server', 'URL', 'Redirected',
    			'MIME Type', 'Title', 'TLS Valid Days', 'TLS Age Days', 'TLS Valid From',
    			'Apex Domain', 'TLS Issuer', 'Status', 'Links', 'Phash', 'Similarity'
			]
			with open(output_file_urlscan, mode='w', newline='', encoding='utf-8') as file:
					writer = csv.writer(file)
					writer.writerow(fields)  # Write the header
			for domain in domains:
				st.subheader(f"Processing Domain: {domain}")
				# Submit the domain to URLScan
				response = requests.post(
					URLSCAN_API,
					headers={'API-Key': api_key, 'Content-Type': 'application/json'},
					json={'url': f'http://{domain}', 'visibility': 'public'}
				)
				if response.status_code == 200:
					scan_id = response.json().get('uuid')
					st.write(f"Submitted to URLScan. Scan ID: {scan_id}")

					# Wait for the scan to complete
					result_url = f"{URLSCAN_RESULT}{scan_id}"
					st.write(f"URLScan result URL (JSON): {result_url}")
					elapsed_time = 0
					placeholder_scan = st.empty()
					time.sleep(10)  # Initial wait
					while elapsed_time < MAX_WAIT_TIME:
						result_response = requests.get(result_url)
						if result_response.status_code == 200:
							placeholder_scan.progress(100, "Scan is still in progress. Waiting...")
							time.sleep(1)
							placeholder_scan.empty()
							result_data = result_response.json()
							screenshot_url = result_data['task']['screenshotURL']
							report_url = result_data['task']['reportURL']
							st.write(f"URLScan Report URL: {report_url}")
							st.markdown(f'''
									- **ASN**: {result_data['page'].get('asn', 'N/A')}
									- **ASN Name**: {result_data['page'].get('asnname', 'N/A')}
									- **Domain**: {result_data['page'].get('domain', 'N/A')}
									- **IP**: {result_data['page'].get('ip', 'N/A')}
									- **Country**: {result_data['page'].get('country', 'N/A')}
									- **Server**: {result_data['page'].get('server', 'N/A')}
									- **URL**: {result_data['page'].get('url', 'N/A')}
									- **Redirected**: {result_data['page'].get('redirected', 'N/A')}
									- **MIME Type**: {result_data['page'].get('mimeType', 'N/A')}
									- **Title**: {result_data['page'].get('title', 'N/A')}
									- **TLS Valid Days**: {result_data['page'].get('tlsValidDays', 'N/A')}
									- **TLS Age Days**: {result_data['page'].get('tlsAgeDays', 'N/A')}
									- **TLS Valid From**: {result_data['page'].get('tlsValidFrom', 'N/A')}
									- **Apex Domain**: {result_data['page'].get('apexDomain', 'N/A')}
									- **TLS Issuer**: {result_data['page'].get('tlsIssuer', 'N/A')}
									- **Status**: {result_data['page'].get('status', 'N/A')}
							''')
							
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
								result_data['page'].get('status', 'N/A')
							]
							if result_data['data']['links']:
								with st.expander("Links Found in the Scan"):
									for link in result_data['data']['links']:
										href = link.get('href', '')
										st.markdown(f"- **URL**: [{href}]({href})")
								data_row.append(result_data['data']['links'])

							if screenshot_url:
								screenshot_response = requests.get(screenshot_url)
								if screenshot_response.status_code == 200:
									screenshot_path = os.path.join(screenshot_folder, f"{domain}.png")
									with open(screenshot_path, 'wb') as screenshot_file:
										screenshot_file.write(screenshot_response.content)
									st.image(screenshot_path, caption=f"Screenshot for {domain} (Screenshots are saved  locally in the {screenshot_folder} folder)")

									# Calculate perceptual hash (pHash) of the screenshot
									screenshot_image = Image.open(screenshot_path)
									screenshot_phash = phash(screenshot_image)
									st.write(f"pHash: {screenshot_phash}")
									data_row.append(screenshot_phash)
									# Compare with the original domain's screenshot (if exists)
									original_screenshot_path = os.path.join(screenshot_folder, f"{original_domain}.png")
									if os.path.exists(original_screenshot_path):
										original_image = Image.open(original_screenshot_path)
										original_phash = phash(original_image)
										distance = screenshot_phash - original_phash
										similarity = (1 - distance / len(screenshot_phash.hash) ** 2) * 100 # hash is a 16-character hex string ⇒ 16 × 4 bits = 64 bits total
										st.success(f"Similarity with {original_domain}: {similarity:.2f}%")
										data_row.append(similarity)
										with st.expander("See explanation"):
											st.write(f"Similarity is calculated as: (1 - distance / {len(screenshot_phash.hash) ** 2}) * 100")
											# Data for the similarity table
											data_explainer = {
												"Similarity %": [
													"100 %",
													"95–99 %",
													"85–94 %",
													"70–84 %",
													"50–69 %",
													"30–49 %",
													"< 30 %",
												],
												"Bit Differences": [
													"0",
													"1–3",
													"4–10",
													"11–19",
													"20–32",
													"33–45",
													"≥ 46",
												],
												"Interpretation": [
													"Identical",
													"Nearly identical",
													"Very similar",
													"Moderately similar",
													"Some resemblance",
													"Low resemblance",
													"Unrelated",
												],
												"Typical Scenarios": [
													"Exact duplicate files; lossless re-saves without pixel changes.",
													"Minor compression artifacts; slight brightness/contrast tweaks.",
													"Small overlays (logos, watermarks); tiny crops or padding.",
													"Moderate JPEG compression; small rotations (≤5°) or scales (≤10 %).",
													"Noticeable edits: blur, color filters, significant cropping.",
													"Heavily stylized or posterized; same scene under different lighting or angle.",
													"Different subjects or scenes; graphic vs. photo.",
												],
											}
											# Create DataFrame
											df_explainer = pd.DataFrame(data_explainer)
											st.write(
												"Use this table to interpret the similarity percentage between two images based on their perceptual hash (pHash)."
											)
											# Display table
											st.dataframe(df_explainer, hide_index=True)                                
								elif screenshot_response.status_code == 404:
									st.error("Screenshot not found. URLScan might not have generated it.")
								else:
									st.error(f"Failed to retrieve screenshot. Status code: {screenshot_response.status_code}")
							# Write the data to the urlscan CSV file
							with open(output_file_urlscan, mode='a', newline='', encoding='utf-8') as file:
								writer = csv.writer(file)
								writer.writerow(data_row)  # Write the data row
							break
						elif result_response.status_code == 404:
							placeholder_scan.progress(elapsed_time, "Scan is still in progress. Waiting...")
							time.sleep(POLL_INTERVAL)
							elapsed_time += POLL_INTERVAL
						else:
							st.error(f"Failed to retrieve scan result: {result_response.text}")
							break
				elif response.status_code == 400:
					st.error("Bad Request. Please check the domain or API request format.")
				else:
					st.error(f"Failed to submit to URLScan: {response.text}")
	else:
		st.error(f"Output file {output_file} not found.")