
# ................
# |   Modules    |
# ................
from datetime import datetime
import whois
from urllib.parse import urlparse
import tldextract
import dns.resolver


# ....................................
# |   Url simplification function    |
# ....................................

def normalize(Url: str) -> dict[str,str]:
    w=urlparse(Url)
    path= w.path

    extracted = tldextract.extract(Url)
    subdomain = extracted.subdomain  
    domain = extracted.domain        
    suffix = extracted.suffix

    return {"Subdomain": subdomain, "Domain": domain, "Suffix": suffix, "path": path}


# ...............................
# |   Domain age Calculation    |
# ...............................

def get_domain_age(domain: str):
    w=whois.whois(domain)
    creation_date=w.creation_date

    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    if creation_date:
            # Ensure creation_date is timezone-aware or naive consistently
        if creation_date.tzinfo is not None:
            now = datetime.now(creation_date.tzinfo)
    
        else:
            now = datetime.now()
    
        age = now - creation_date
        return {
            "Days": int(age.days),
            "Months": int(age.days/30),
            "Years" : int(age.days/365)
        }


# .....................
# |   Url DNS Info    |
# .....................

def get_DNS_info(domain:str)->dict:
    records={}
    resolver = dns.resolver.Resolver()
    resolver.timeout  = 10   # wait per server
    resolver.lifetime = 10   # total budget
    resolver.nameservers = [
        "1.1.1.1",   # Cloudflare
        "8.8.8.8",   # Google
    ]
    for rtype in ('A','MX','NS'):
        try:
            records[rtype]=[r.to_text() for r in resolver.resolve(domain,rtype)]
        except dns.resolver.LifetimeTimeout:
            records[rtype]="timeout"
        except dns.resolver.NoAnswer:
            records[rtype] = "no record of this type"
        except dns.resolver.NXDOMAIN:
            records[rtype] = "domain does not exist"
    return records

# ..............................
# |   URL redirect url list    |
# ..............................

import requests

def check_redirects(url)->list:
    response_list=[]
    try:
        response = requests.get(url,allow_redirects=True,timeout=10)
        
        if response.history:
            for resp in response.history:
                response_list.append(f"{resp.url}")
        else:
            response_list.append("None")
        response_list.append(f"{response.url}")
    except requests.exceptions.RequestException as e:
        response_list.append(f"Error: {e}")
    return response_list

# ............................
# |   Url Result function    | 
# |  (Main function to Run)  |
# ............................

def analyzation(Url)-> dict:
    try:
        domain=[normalize(Url)["Domain"],normalize(Url)["Suffix"]]
        domain_name= ".".join(domain)
        return {
            "Url": Url,
            "parts": normalize(Url),
            "DNS-Info": get_DNS_info(domain_name),
            "Age": get_domain_age(domain_name),
            "redirects": check_redirects(Url)
            }
    except Exception as e:
        print("Error:",e)   #change this to add or use anything as error


