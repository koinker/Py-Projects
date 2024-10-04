import dns
import dns.resolver
import socket

def ReverseDNS(ip):
    try:
        result = socket.gethostbyaddr(ip)
    except:
        return []
    return [result[0]]+result[1]

def DNSRequest(domain):
    try:
        result = dns.resolver.resolve(domain,'A')
        if result:
            print(domain)
            for answer in result:
                print(answer)

                r_answer = ReverseDNS(answer.to_text())
                print(f"Domain Names: {r_answer}")
    except (dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoAnswer):
        return
        

def SubdomainSearch(domain, dictonary, nums):
    for word in dictionary:
        subdomain = word+"."+domain
        DNSRequest(subdomain)
        if nums:
            for i in range(0,10):
                s = word+str(i)+"."+domain
                DNSRequest(s)

if __name__ == "__main__":

    domain = input("Enter Domain: ")
    d = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    with open(d,"r") as f:
        dictionary = f.read().splitlines()
    SubdomainSearch(domain,dictionary,False)
