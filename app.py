import os
import requests
import base64
import streamlit as st
from google import genai
from google.genai import types
from dotenv import load_dotenv
from bs4 import BeautifulSoup



def shodan_ip_tool() -> str:
    """
    From given target IP address, 
    extract and summarize the following network and cloud infrastructure insights from shodan.io website:

    Hostnames associated with the IP.
    Domains linked to the IP.
    Cloud provider and related metadata (e.g., region, service type).
    Geolocation details (country, city).
    Organization and ISP information.
    Autonomous System Number (ASN).
    Open ports and their responses, including HTTP headers and status codes.
    SSL Certificate:  Signature Algorithm, 
                      Signature 
                      Signature Value.
                      
    Provide an exhaustive yet comprehensive summary of the extracted insights.
    """
    
    prompt="""
    extracts from given user message if exists the IP 
    such as 20.111.12.195 ad return only the ip
    """
    
    extracte_ip = client.models.generate_content(
        model='gemini-1.5-flash',
        contents=[prompt, user_message]
    )

    url = f"https://www.shodan.io/host/{extracte_ip.text}"
    response = requests.get(url=url)
    
    soup = BeautifulSoup(response.text, 'html.parser')
    element = soup.find(id='host')
    text_element = element.get_text()
    
    return text_element


def virus_total_url_tool() -> str:
    """
    Given the URL {insert_url_here}, analyze and extract 
    key insights related to its security, metadata, and reputation. 
    
    Make sure the analysis includes:

    URL reputation score
    Any detected threats or security risks
    Page metadata (title, headers, content hash)
    External links and redirections
    Last submission and modification timestamps
    Category classification from various security engines
    Final resolved URL and content-related details
    If no threats are detected, ensure that the threat_names list remains empty, 
    and all security scans should return "result": "clean" where applicable."""
    
    prompt="""
    extracts from given user message if exists the url 
    such as https://www.facebook.it/ ad return only the url
    """
    
    extracted_url = client.models.generate_content(
        model='gemini-1.5-flash',
        contents=[prompt, user_message]
    )
    
    virus_total_url_text = extracted_url.text

    url_id = base64.urlsafe_b64encode(f"{virus_total_url_text}".encode()).decode().strip("=")

    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {
        "accept": "application/json",
        "x-apikey": f"{virus_total_api_key}"}

    response = requests.get(url, headers=headers)
    text_response = response.text
    
    return text_response


def virus_total_domain_tool() -> str:
    """
    Extract the following domain information in JSON format: 
    
    Analysis for given domain [domain_name] returned the following insights:
    
    domain name, 
    WHOIS details (creation date, expiration date, last update, organization, DNSSEC status), 
    last DNS records (including record type, TTL, value, and additional details such as MX priority or SOA serial), 
    last HTTPS certificate details (issuer, validity period, public key details, signature, subject alternative names, key usage), 
    last analysis statistics (number of malicious, suspicious, undetected, harmless, and timeout results), 
    domain reputation score, and JARM fingerprint. 
    
    Ensure the response maintains the original structure with properly nested attributes. 
    """
    
    prompt="""
    extracts from given user message if exists the domain 
    such as google.it ad return only the domain
    """
    
    extracted_domain = client.models.generate_content(
        model='gemini-1.5-flash',
        contents=[prompt, user_message]
    )
    
    domain_name = extracted_domain.text
    
    cleaned_domain = domain_name.strip()

    url = f"https://www.virustotal.com/api/v3/domains/{cleaned_domain}"

    headers = {
        "accept": "application/json",
        "x-apikey": f"{virus_total_api_key}"}

    response = requests.get(url, headers=headers)
    text_response = response.text
    
    return text_response


def virus_total_hash_tool() -> str:
    """Given a file hash, such as: 36dcecf08fa6b87702650c71c340aee613febd9de34bc2330791da358502cc4a, 
    extract cybersecurity-related information about the corresponding file.

    The output should highlight:

    File hash identifiers (sha256, sha1, md5)
    Meaningful file name and aliases
    File size
    Latest antivirus scan statistics (number of malicious, suspicious, undetected, etc.)
    Last modification and submission dates
    Tags and identified file type
    Antivirus scan results, including engine name, category, and detection result
    """
    
    prompt="""
    extracts from given user_message if exists, the hash 
    such as 36dcecf08fa6b87702650c71c340aee613febd9de34bc2330791da358502cc4a
    ad return only the hash.
    """
    
    extracted_hash = client.models.generate_content(
        model='gemini-1.5-flash',
        contents=[prompt, user_message]
    )
    hash_name = extracted_hash.text

    cleaned_hash = hash_name.strip()

    url = f"https://www.virustotal.com/api/v3/files/{cleaned_hash}"
    
    headers = {
        "accept": "application/json",
        "x-apikey": f"{virus_total_api_key}"}
    
    response = requests.get(url, headers=headers)
    text_response = response.text
    
    return text_response
    
    


if __name__ == '__main__':
    
    load_dotenv('.env')
    # google_api_key = os.getenv('GOOGLE_API_KEY')
    # virus_total_api_key = os.getenv('VIRUS_TOTAL_API_KEY')
    
    google_api_key = st.secrets["GOOGLE_API_KEY"]
    virus_total_api_key = st.secrets["VIRUS_TOTAL_API_KEY"]
    client = genai.Client()

    st.title('Ai NetRunner CyberTool')
    
    st.markdown("""
    - 🔍 **IP Analysis** → Performed using [Shodan.io](https://www.shodan.io/)
    - 🌐 **Domain Analysis** → Performed using [VirusTotal](https://www.virustotal.com/)
    - 🔗 **URL Analysis** → Performed using [VirusTotal](https://www.virustotal.com/)
    - 🔑 **Hash Analysis** → Performed using [VirusTotal](https://www.virustotal.com/)
    """)
    
    st.image("https://www.wallpaperflare.com/static/66/41/250/cyberpunk-futuristic-computer-interfaces-wallpaper.jpg", 
             caption="", use_container_width=True)

    user_message = str(st.text_area('Insert your query: '))
        
    if st.button("Analyze"):
        if user_message.strip():  
            with st.spinner("Generating response... Please wait."):
                try:
                    response = client.models.generate_content(
                        model='gemini-1.5-pro',
                        contents=user_message,
                        config=types.GenerateContentConfig(
                            tools=[shodan_ip_tool, 
                                virus_total_url_tool, 
                                virus_total_domain_tool,
                                virus_total_hash_tool],
                        ),
                    )
                    
                    print(response.text)
                    st.success("Generated Answer:")
                    st.write(response.text)

                except Exception as e:
                    st.error(f"Error during content generation: {e}")
        else:
            st.warning("Insert your message before generating the answer!")

        
    


    

