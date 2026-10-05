import ipaddress

import os

import requests

api_key = os.getenv("VIRUSTOTAL_API_KEY")

if not api_key:

    print("[!] VIRUSTOTAL_API_KEY is not configured")

    exit()

def display_stats(stats):

    print(f"Malicious detections: {stats['malicious']}")
    print(f"Suspicious detections: {stats['suspicious']}")
    print(f"Harmless detections: {stats['harmless']}")
    print(f"Undetected: {stats['undetected']}")

    if stats["malicious"] > 0:
    
        print("[!] Verdict: MALICIOUS")

    elif stats["suspicious"] > 0:

        print("[!] Verdict: SUSPICIOUS")

    else:

        print("[+] Verdict: CLEAN")

def is_ip(value):

    try:

        ipaddress.ip_address(value)
        return True 
   
    except ValueError:
        return False

def is_domain(value):

    if "." in value and " " not in value and not value.startswith (".") and not value.endswith("."):

         return True

    else:
        
        return False

def is_hash(value):

    valid_chars = "0123456789abcdef"

    valid_lengths = [32, 40, 64] 

    valid_hash = all(char in valid_chars for char in value.lower())

    if len(value) in valid_lengths and valid_hash:

        return True

    else: 

        return False


def get_hash_type(value):

    if len(value)  == 32:

        return "MD5"

    elif len(value) == 40:

        return "SHA-1"

    elif len(value) == 64:

        return "SHA-256"

def check_domain_virustotal(domain):

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    headers = {

        "x-apikey": api_key
    }

    try:
 
       response = requests.get(url, headers=headers)

    except requests.exceptions.RequestException:

         print("[!] Connection error")

         return

    if response.status_code == 200:
    
        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        display_stats(stats)
        
def check_ip_virustotal(ip):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
    
        "x-apikey": api_key
    
    }

    try:

        response = requests.get(url, headers=headers)

    except requests.exceptions.RequestsException:

         print("[!] Connection error")

         return

    if response.status_code == 200:

        data = response.json()
 
        stats = data["data"]["attributes"]["last_analysis_stats"]
    
        display_stats(stats)
        
    else:

        print(f"[!] VirusTotal API error: {response.status_code}")


def check_hash_virustotal(file_hash):

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {

        "x-apikey": api_key

    }

    try:

        response = requests.get(url, headers=headers)

    except requests.exceptions.RequestException:
 
        print("[!] Connection error")

        return

    if response.status_code == 200:
    
        data = response.json()
        
        stats = data["data"]["attributes"]["last_analysis_stats"]
     
        display_stats(stats)
      
    elif response.status_code == 404:

        print("[!] IOC not found in VirusTotal")     

    elif response.status_code == 401:
  
        print("[!] Authentication error: check your API key")

    elif response.status_code == 429:
  
        print("[!] Rate limit exceeded: too many requests")

    else:
            
        print(f"[!] VirusTotal API error: {response.status_code}")            

ioc = input("Enter an IOC: ")

if is_ip(ioc):

    print("IOC Type: IP Address")

    check_ip_virustotal(ioc)

elif is_domain(ioc):
    
    print("IOC Type: Domain")

    check_domain_virustotal(ioc)

elif is_hash(ioc):
   
    print(f"IOC Type: Hash ({get_hash_type(ioc)})")

    check_hash_virustotal(ioc)
    
else:
 
    print("Unknown IOC Type")





