import requests
import ipaddress
# test
# ------------
# API variables
# ------------

# For getting the IP address
ipapiUrl = "http://ip-api.com/json/"

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
    

# Function to output the results
def output(ipresult):
    print("--------------------------------")
    if ipresult:
        print(f"IP Address: {ipresult.get("query")}")
        print(f"Country: {ipresult.get("country")}")
        print(f"Region: {ipresult.get("regionName")}")
        print(f"City: {ipresult.get("city")}")
        print(f"Coordinates: (Latitude) {ipresult.get("lat")}, (Longitude) {ipresult.get("lon")}")
        print(f"ISP: {ipresult.get("isp")}")
    print("--------------------------------") 
    
    # Add other output here

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
    
    # ADD OTHER CODE HERE
    
    # Display the output
    output(ipResult)

