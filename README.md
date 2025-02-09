# AI NetRunner CyberTool

![ai-netrunner-cybertool](https://www.wallpaperflare.com/static/66/41/250/cyberpunk-futuristic-computer-interfaces-wallpaper.jpg)

### Overview

AI NetRunner CyberTool is a Streamlit-based cybersecurity application designed to analyze and extract insights about IP addresses, domains, URLs, and file hashes. It leverages Google Gemini AI, Shodan, and VirusTotal APIs to perform deep scans and provide detailed reports on network security and cyber threats.

### Features

🔍 IP Analysis: Extracts data from Shodan.io to analyze hostnames, domains, geolocation, ISP, ASN, open ports, HTTP headers, SSL certificate details, and more.

🌐 Domain Analysis: Uses VirusTotal to retrieve WHOIS data, DNS records, HTTPS certificate details, reputation score, and security statistics.

🔗 URL Analysis: Analyzes URLs via VirusTotal, providing information on threats, metadata, redirects, and reputation scores.

🔑 Hash Analysis: Extracts cybersecurity insights about files from VirusTotal, including antivirus scan results, file size, tags, and submission history.

### Installation

Ensure you have the following installed:

 - Python 3.8+

 - Pip

Clone the Repository:

```bash 
git clone https://github.com/yourusername/ai-netrunner-cybertool.git 
```
```bash
cd ai-netrunner-cybertool
```
Create a virtual environment:
```bash
python -m venv .venv
cd .venv/Scripts/
./activate
```
or for linux: 
```bash
source .venv/bin/activate
```

Install Dependencies:

```bash
pip install -r requirements.txt
```

Set Up API Keys:

Create a .env file in the project directory and add your API keys:

```bash
GOOGLE_API_KEY="your_google_api_key"
SHODAN_API_KEY="your_shodan_api_key"
VIRUS_TOTAL_API_KEY="your_virustotal_api_key"
```

Alternatively, you can store them in Streamlit secrets:

```bash
st.secrets["GOOGLE_API_KEY"] = "your_google_api_key"
st.secrets["VIRUS_TOTAL_API_KEY"] = "your_virustotal_api_key"
```

### Usage

Run the Application locally:

```bash
streamlit run app.py
```

Run the Application already deployed on the cloud:

https://ai-netrunner-cybertool.streamlit.app/ 

### Interface

- Enter an IP address, domain, URL, or file hash in the input field.

- Click Analyze to retrieve and display security insights.

- View results directly within the Streamlit interface.

After running an analysis, you will receive structured cybersecurity reports including:

- IP-related details (ISP, location, ASN, ports, SSL certificates, etc.)

- Domain WHOIS records and reputation scores

- URL scan results and threat intelligence

- File hash lookup results with antivirus detections


### License

This work is licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0). You may copy, distribute, and adapt the material, provided you give appropriate credit, indicate if changes were made, and do not suggest the licensor endorses you or your use. To view a copy of this license, visit https://creativecommons.org/licenses/by/4.0/.

### Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.