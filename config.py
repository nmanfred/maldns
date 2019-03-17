with open('vtapikey', 'r', newline ='') as apikeyfile:
    apikey = apikeyfile.read().strip()

# MUST BE SET BEFORE RUNNING
interface = "wlp3s0" # use ifconfig or ipconfig to find the name of your interface
#interface = "en0"

private_access = False # set to True if you subscribe to VirusTotal private access
