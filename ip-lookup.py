import os
import requests
import ipaddress
# ------------
# API variables
# ------------

# For getting the IP address
ipapiUrl = "http://ip-api.com/json/"

# For checking if the IP is reported on AbuseIPDB
abuseIpDbUrl = "https://api.abuseipdb.com/api/v2/check"

# API Key (hardcoded)
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "732e8aca720a72fbcaef825815908d99a3315b93fb8632ba93ef948f060d6526d75bf9d5938d89f5")


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
    
# Function to create a Google Maps link from coordinates
def getMapLink(lat, lon):

    # Ensures that latitude and longitude exists before creating the link
    if lat is not None and lon is not None:
        return f"https://www.google.com/maps?q={lat},{lon}"
    return "Map link unavailable"

# Function to output the results
def output(ipresult, abuseresult=None):
    print("--------------------------------")

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
    else:
        print("Could not retrieve IP geolocation data.")
     
    # AbuseIPDB Report Result
    print("--------------------------------")
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
    print("--------------------------------")


    
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
    
    # Display the output
    output(ipResult, abuseResult)

