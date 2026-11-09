# API variables


# Main loop
while True:
    ip = input("Input an IP address [your IP]: ")
    if ip == "q" or ip == "quit":
        break
    # Determine if the user chose his own IP or a custom IP
    if ip == "":
        print("Calling my IP")
    else:
        print("Calling custom IP")

# def isValidIp(ip):
    

def getIpApi():
    print("Getting IP...")