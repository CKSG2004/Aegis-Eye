import socket

def find_subdomains(domain, wordlist_path="scanner/wordlists/subdomains.txt"):
    found = []
    with open(wordlist_path, 'r') as file:
        for line in file:
            sub = line.strip()
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                found.append({"subdomain": subdomain, "ip": ip})
            except socket.gaierror:
                continue  # Skip if subdomain doesn't resolve
    return found
