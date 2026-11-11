import os
import re
import subprocess
import requests
import ipaddress
from dotenv import load_dotenv

load_dotenv()

# ------------
# API variables
# ------------

# For getting the IP address
ipapiUrl = "http://ip-api.com/json/"

# For checking if the IP is reported on AbuseIPDB
abuseIpDbUrl = "https://api.abuseipdb.com/api/v2/check"

# Get API key from .env
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# ------------
# Functions
# ------------

# Function to get ip information from ip-api.com
def getIpApi(ip=""):
    url = ipapiUrl
    try:
        # If ip is present, append it to the url call
        if ip:
            url += f"/{ip}"
        
        # Query and return JSON response
        response = requests.get(url)
        return response.json()
    
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

# Function to check if IP is reported on AbuseIPDB
def checkAbuseIpDb(ip):
    if not ip:
        return None

    # Setup API Key and return JSON data
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    # Look for the IP we want to report from the last 90 days
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"  # Checks reports from the last 90 days
    }

    try:
        response = requests.get(abuseIpDbUrl, headers=headers, params=params, timeout=5)

        # Upon successful response
        if response.status_code == 200:
            return response.json().get("data")

        # Upon failure (Incorrect API Key)
        elif response.status_code == 401:
            print("AbuseIPDB Error: Invalid or missing API Key.")
            return None

        # Failback (other errors)
        else:
            print(f"AbuseIPDB Error: HTTP {response.status_code}")
            return None

    # Coud not reach AbuseIPDB API
    except Exception as e:
        print(f"An error occurred querying AbuseIPDB: {e}")
        return None


# Function to check if the ip is valid
def isValidIp(ip):
    # First check if the input is empty
    # If so, it is still considered valid
    if ip == "": return True
    
    # Check for the validity using the ipaddress library
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Function to check if the target IP is reachable and measure latency (ping)
def checkLatency(ip):
    if not ip:
        return None

    # Windows uses '-n' for packet count, while Mac/Linux uses '-c'
    param = "-n" if os.name == "nt" else "-c"
    command = ["ping", param, "2", ip]

    try:
        # Run the ping command in the background and capture the text output
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=6)
        
        # returncode 0 means at least one ping got a reply
        if result.returncode == 0:
            # Look for the average time in the ping output (works on Windows and Mac/Linux)
            match = re.search(r"Average = (\d+ms)|min/avg/max/[a-z]+ = [\d.]+/([\d.]+)/", result.stdout)
            if match:
                avg_ping = match.group(1) or f"{match.group(2)}ms"
                return f"Reachable (Avg Latency: {avg_ping})"
            return "Reachable"
        else:
            return "Unreachable (Request timed out or blocked by firewall)"
            
    except Exception:
        return "Unreachable (Ping check failed)"
       
# Function to create a Google Maps link from coordinates
def getMapLink(lat, lon):

    # Ensures that latitude and longitude exists before creating the link
    if lat is not None and lon is not None:
        return f"https://www.google.com/maps?q={lat},{lon}"
    return "Map link unavailable"

# Function to check if the ip is valid
def isValidIp(ip):

    #  Check if the input is empty
    if ip == "": return True
    
    # Check for the validity using the ipaddress library
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
    
# Function to output the results
def output(ipresult, abuseresult=None, latencyresult=None):
    print("----------------------------------------")

    # Ensures that we are able to get an IP from the lookup
    if ipresult and ipresult.get("status") == "success":
        target_ip = ipresult.get("query")

        # Check if the address is IPv4 or IPv6
        ip_version = f"IPv{ipaddress.ip_address(target_ip).version}" if target_ip else "Unknown"

        # Grab coordinates and generate the Google Maps URL
        lat = ipresult.get("lat")
        lon = ipresult.get("lon")
        map_link = getMapLink(lat, lon)

        # Print out the location & ISP information
        print(f"IP Address: {ipresult.get("query")} ({ip_version})")
        print(f"Country: {ipresult.get("country")}")
        print(f"Region: {ipresult.get("regionName")}")
        print(f"City: {ipresult.get("city")}")
        print(f"Coordinates: (Latitude) {ipresult.get("lat")}, (Longitude) {ipresult.get("lon")}")
        print(f"Map Link:    {map_link}")
        print(f"ISP: {ipresult.get("isp")}")
        print(f"ASN:          {ipresult.get('as')}")
        print(f"Reachability: {latencyresult}")
    else:
        print("Could not retrieve IP geolocation data.")
     
    # AbuseIPDB Report Result
    print("----------------------------------------")
    if abuseresult:

        # Extract report data from the AbuseIPDB response
        total_reports = abuseresult.get("totalReports", 0)
        confidence_score = abuseresult.get("abuseConfidenceScore", 0)
        last_reported = abuseresult.get("lastReportedAt") or "Never"
        usage_type = abuseresult.get("usageType") or "Unknown"
        is_whitelisted = abuseresult.get("isWhitelisted")

        # Decide if the IP is actually risky based on the confidence score
        if confidence_score >= 25:
            status = "REPORTED / SUSPICIOUS"
        elif total_reports > 0:
            status = "SAFE (Reported, but 0% Abuse Confidence)"
        else:
            status = "CLEAN (No Reports)"

        # Display the security report summary   
        print(f"Status:            {status}")
        print(f"Total Reports:     {total_reports} (in last 90 days)")
        print(f"Abuse Confidence:  {confidence_score}%")
        print(f"Usage Type:        {usage_type}")
        print(f"Whitelisted:       {is_whitelisted}")
        print(f"Last Reported At:  {last_reported}")
        print(f"Web Report Link:   https://www.abuseipdb.com/check/{abuseresult.get('ipAddress')}")
    else:
        print("AbuseIPDB data unavailable.")
    print("----------------------------------------")


    
# ------------
# Main loop
# ------------
while True:
    ip = input("Input an IP address [your IP]: ")
    if ip == "q" or ip == "quit":
        break
    
    # First check the validity of the ip address
    ipValid = isValidIp(ip)
    if not ipValid: 
        print("Invalid IP, please try again.")
        continue
    
    # Determine if the user chose his own IP or a custom IP
    ipResult = ""
    if ip == "":
        ipResult = getIpApi()
    else:
        ipResult = getIpApi(ip)
    
   # Extract the resolved IP address
    resolvedIp = ipResult.get("query") if ipResult else ip

    # Query AbuseIPDB using the resolved IP address
    abuseResult = checkAbuseIpDb(resolvedIp)
    latencyResult = checkLatency(resolvedIp)
    
    # Display the output
    output(ipResult, abuseResult, latencyResult)

