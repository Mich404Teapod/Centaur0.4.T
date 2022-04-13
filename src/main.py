import os
import hashlib
import logging
import argparse
from datetime import datetime
from lib.colors import red,white,red,reset, green
try:
	import requests
except ImportError:
	print(f"{white}[{green}*{white}] Installing missing module(s). Please wait...{reset}")
	os.system('pip install requests==2.26.0')
	exit(f"{white}[{green}+{white}] Installation complete!. Run program again.{reset}")


logging.basicConfig(format=f"{white}[{green}*{white}] %(message)s{reset}",level=logging.DEBUG)

class Centaur:
    def __init__(self,args):
        self.api = "https://www.virustotal.com/vtapi/v2/"
        self.apikey = "Virus Total API key" 
    
    def on_start(self):
    	if args.scan:
    		self.scan()
    	elif args.hash:
    		self.hash()	
    	elif args.domain:
    		self.domain()
    	elif args.ip:
    		self.ip()
    	else:
    		exit(f"{white}centaur: use {green}-h{white} or {green}--help{white} for usage.{reset}")
    		
    # Scanning IP		   		   		
    def ip(self):
    	api = f"{self.api}ip-address/report"
    	params = {"ip":args.ip, "apikey":self.apikey}
    	request = requests.get(api, params=params)
    	resp = request.json()
    	results = self.parse_resp(resp)
    	
    	if results['response_code'] <= 0:
    		print(f"{white}[{red}!{white}] {results['verbose_msg']}{reset}")
    	else:
    		print(f"{white}[{green}#{white}] {results['verbose_msg']}{reset}\n")
    		print(f"{white}Owner: {green}{results['as_owner']}{reset}")
    		print(f"{white}ASN: {green}{results['asn']}{reset}")
    		print(f"{white}Country: {green}{results['country']}{reset}")
    		print(f"\n{white}DETECTED URL's\n",end=f"{white}-{reset}"*73)
    		print(f"\n{white}URL         |    Detection ratio    |    Scan date\n",end='-'*73)
    		for item in results['detected_urls']:
    		    for key,value in item.items():
    		    	print(f"\n{red}{item['url']}     {red}{item['positives']}{white}/{item['total']}{red}           {item['scan_date']}{reset}")
    		    	
    		print(f"\n\n\n{white}RESOLUTIONS{reset}\n",end=f"{white}-{reset}"*40)    	
    		print(f"\n{white}Hostname   |   Last resolved{white}\n",end='-'*40)
    		print(f"\n{reset}")
    		for item in results['resolutions']:
    		    for key,value in item.items():
    		        print(f"{red}{item['hostname']}    {item['last_resolved']}{reset}")
 
    		        
    		print(f"\n\n\n{white}DETECTED COMMUNICATING SAMPLES{reset}")
    		print(f"{white}-{reset}"*82)
    		print(f"{white}SHA-256                                                        | Detection ratio{white}\n",end='-'*82)
    		print(f"\n{reset}")
    		for item in results['detected_communicating_samples']:
    		    for key,value in item.items():
    		        print(f"{red}{item['sha256']}         {item['positives']}{white}/{item['total']}{red}{reset}\n")
    		             

   
    # Getting file scan results (will need file resource/scan id  which is a SHA-256 hash)
    def scan(self):
    	api = f"{self.api}file/report"
    	params = {"resource":args.scan,"apikey":self.apikey}
    	request = requests.post(api, data=params)
    	resp = request.json()
    	results = self.parse_resp(resp)
    	
    	if results["response_code"] <= 0:
    	    print(f"{white}[{red}!{white}] {results['verbose_msg']}{reset}")
    	else:
    	    print(f"{white}[{green}#{white}] {results['verbose_msg']}{reset}")
    	    
    	    if results['positives'] <= 0:
    	        color = green
    	    else:
    	    	color = red
    	    	
    	    print(f"\n\n{white}SUMMARY{reset}")
    	    print(f"{white}-{reset}"*73)
    	    print(f"{color}{results['positives']}{white}/{results['total']} Security vendors flagged this file as malicious{reset}")
    	    print(f"\n{white}MD5: {color}{results['md5']}{reset}")
    	    print(f"{white}SHA-256: {color}{results['sha256']}{reset}")
    	    print(f"{white}Scan time: {color}{results['scan_date']}{reset}")
    	    print(f"\n\n\n{white}DETECTION{reset}")
    	    print(f"{white}-{reset}"*73)
    	    print(f"{white}Security vendor  |    Result    |    Update\n",end='-'*73)
    	    print("\n")
    	    for vendor, detection in results['scans'].items():
    	        if detection['result'] is None:
    	        	result = "Undetected"
    	        	color = green
    	        else:
    	        	result = detection['result']
    	        	color = red
    	        print(f"{white}{vendor}		    {color}{result}      {white}{detection['update']}{reset}")
  		
    # Scanning domain		
    def domain(self):
        api = f"{self.api}domain/report"
        params = {"domain":args.domain, "apikey":self.apikey}
        request = requests.get(api, params=params)
        resp = request.json()
        results = self.parse_resp(resp)
        if results['response_code'] <= 0:
            print(f"{white}[{red}!{white}] {results['verbose_msg']}{reset}")
        else:
            print(f"{white}[{green}#{white}] {results['verbose_msg']}{reset}\n")
            print(f"\n\n{white}WHOIS{reset}\n",end=f"{white}-{reset}"*70)
            print(f"\n{white}{results['whois']}{reset}")                    
            print(f"\n\n{white}SUBDOMAINS{reset}\n",end=f"{white}-{reset}"*25)
            print("\n")
            for domain in results['subdomains']:
                print(f"{white}{domain}{reset}")
                    
            print(f"\n\n{white}RESOLUTIONS{reset}\n",end=f"{white}-{reset}"*40)
            print(f"\n{white}IP            |   Last resolved{reset}\n",end=f"{white}-{reset}"*40)
            print("\n")
            for item in results['resolutions']:
                for key,value in item.items():
                    print(f"{red}{item['ip_address']}   {white}{item['last_resolved']}{reset}")
                    
            print(f"\n\n{white}DETECTED URL's{reset}\n",end=f"{white}-{reset}"*73)
            print(f"\n{white}URL         |    Detection ratio    |    Scan date\n",end=f"{white}-{reset}"*73)
            print("\n")
            for item in results['detected_urls']:
                for key,value in item.items():
                    print(f"{red}{item['url']}     {red}{item['positives']}{white}/{item['total']}{red}           {item['scan_date']}{reset}")
                                
        
    # Hashing a potential malicious file
    # The generated hash will be used to get scan results    
    def hash(self):
        block_size = 65536
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(args.hash, 'rb') as file:
            buf = file.read(block_size)
            while len(buf) > 0:
                md5_hash.update(buf)
                sha256_hash.update(buf)
                buf = file.read(block_size)
                
            print(f"MD5: {md5_hash.hexdigest()}")
            print(f"SHA-256: {sha256_hash.hexdigest()}")
                
        	
    # Parsing response
    def parse_resp(self,resp):
    	buf = {}
    	for item in resp:
    		buf[item] = resp[item]
    	return buf
    	

start = datetime.now()
parser = argparse.ArgumentParser(description=f"{white}Lightwheight malware analysis tool{reset}",epilog=f"{white}Centaur.04 uses {green}Virus Total{white} to analyze files, IP addresses, URL's and domains for malware or malicious activities, with the help of top rated security vendors. Program developed by {green}Richard Mwewa{white} (@rly0nheart | https://about.me/{green}rlyonheart{white}){reset}")
parser.add_argument("--hash",metavar=f"{white}path/to/file{reset}")
parser.add_argument("--scan",help=f"{white}hash of potential malicious file{reset}", metavar=f"{white}md5/sha256 hash{reset}")
parser.add_argument("--domain",help=f"{white}scan domain{reset}", metavar=f"{white}DOMAIN{reset}")
parser.add_argument("--ip",help=f"{white}scan ip address{reset}", metavar=f"{white}IP{reset}")
parser.add_argument("--version",action="version",version=f"{white}v2022.1.0.1-beta{reset}")
args = parser.parse_args()
