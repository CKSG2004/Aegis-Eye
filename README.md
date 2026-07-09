Aegis Eye

Aegis Eye is a robust, lightweight network and web security scanning utility built on the Flask framework.
The project is designed with built-in network discovery tools and automated multi-threaded scanning capabilities, making it ideal for standard security audits and vulnerability mapping.

Project Architecture
The core logic of the scanner is modularly structured as follows:
Aegiseye
├── app.py                      # Flask Application Root (Routing & Controller)

├── requirements.txt            # Project Dependency Blueprint

├── templates/

│   ├── index.html              # Scanner Dashboard Interface

│   └── result.html             # Scan Reports & Analytics Display

└── scanner/

    ├── fingerprint.py          # OS & System Service Fingerprinting
    
    ├── http_headers.py         # Security Header Analysis Utility
    
    ├── port_scan.py            # Multi-threaded TCP/UDP Port Scanner
    
    ├── subdomain_finder.py     # Target Subdomain Enumeration Module
    
    ├── vuln_scan.py            # Core Vulnerability Assessment Engine
    
    └── wordlists/
    
        └── subdomains.txt      # Subdomain Brute-forcing Wordlist
        
Key Modules

•	Vulnerability Assessment (vuln_scan.py): Automatically benchmarks networks against common exploit paths.

•	Network Mapper (port_scan.py): Fast multi-threaded port discovery engine to identify open ports and entry nodes.

•	Subdomain Enumerator (subdomain_finder.py): Uses custom wordlists to unearth hidden infrastructure or forgot-about staging domains.

•	Header Auditor (http_headers.py): Analyzes server configurations for missing cryptographic protections and loose security policies.


Local Setup & Installation
Follow these steps to set up and run Aegis Eye locally on your machine.
1. Clone the Repository
git clone https://github.com/CKSG2004/Aegis-Eye.git
2. Set Up an Isolated Virtual Environment
python -m venv venv
3. Activate the Environment (Windows PowerShell)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
4. Install Dependencies
pip install -r requirements.txt
5. Run the Application
python app.py
