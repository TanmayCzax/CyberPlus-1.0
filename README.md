# CyberPlus 1.0
**EASY**
**FAST**
**SAFE&SECURE**
# Official Website https://cyberpluslang.pages.dev

# Cyber+   
**An Ethical Cyber Security Programming Language**

Cyber+ is a domain‑specific programming language (DSL) designed for **ethical hacking, cybersecurity learning, and security automation**.  
It allows users to perform reconnaissance, OSINT, security analysis, and simulations using **simple, readable scripts** (`.cbp` files).

>  Cyber+ is built strictly for **ethical, educational, and defensive security purposes only**.

---

##  Features

-  Network & Web Reconnaissance
-  DNS, IP, SSL, WHOIS intelligence
-  Hashing, encoding, password utilities
-  Security header & HTTPS audits
-  Ethical attack simulations
-  JSON & HTML report generation
-  Fast Go‑based runtime
-  Simple `.cbp` scripting syntax

---

##  Installation

### Clone the repository

**git clone https://github.com/TanmayCzax/CyberPlus-1.0**

cd Cyber-Programming-language-Alpha/Golang

# Usage
# 1 Check version

**./cyberplus --version**

# 2 Run a Cyber+ script

**./cyberplus run filename.cbp**

# 3 Build a script into an executable (experimental)

**./cyberplus build exe filename.cbp**
# Example .cbp Script
# cbp

Compute("Cyber+ Recon Started");

Web_Fingerprint("example.com");
HTTP_Security_Audit("example.com");
Port_Probe("scanme.nmap.org");
DNS_Intel("example.com");

Export_Report("json");


# RUN IT:
./cyberplus run example.cbp

# Supported Commands 
# 1 Engine Control
-- run Cyber+ Activates the Cyber+ execution engine.

# 2 Core / Output
Compute("text"); Prints text output to the console.

# 3 Network Scanning & Connectivity
Scan_Port("ip", port); Checks whether a TCP port is open or closed.

Ping("host"); Sends a single ping request to a host.

Traceroute("host"); Displays the network path to a host.

NetworkScan("ip_start-ip_end", [ports]); Simulated ethical network scan over an IP range.

# 4 DNS & Domain Intelligence
Dns_Lookup("domain"); Resolves domain to IP addresses.

Subdomain_Enum("domain"); Enumerates subdomains using certificate transparency logs.

Reverse_IP("ip"); Resolves domain names hosted on an IP.

DomainAge("domain"); Retrieves domain registration information.

# 5 IP Intelligence & OSINT
IP_Info("ip"); Fetches detailed IP information.

GeoIP("ip"); Retrieves geographical data of an IP address.

# 6 Web & URL Analysis
URL_Status("url"); Checks HTTP response status of a URL.

HTTP_Headers("domain"); Displays all HTTP response headers.

Check_Headers_Security("domain"); Detects missing security-related HTTP headers.

# 7 SSL / TLS Analysis
SSL_Info("domain"); Displays SSL certificate issuer and expiry.

CheckSSLvulnerabilities("domain"); Simulated SSL vulnerability analysis.

# 8 WHOIS & Registration
Whois("domain"); Retrieves WHOIS data for a domain.

# 9 OSINT – Phone & Email
Phone_Info("phone_number"); Provides phone number intelligence.

EmailVerify("email"); Performs email format validation.

# 10 Encoding, Hashing & Utilities
Hash_Compute("text", "algorithm"); Generates hashes using md5, sha1, or sha256.

Base64_Encode("text"); Encodes text using Base64.

Base64_Decode("encoded_text"); Decodes Base64-encoded text.

Generate_Password(length); Generates a random secure password.

# 11 Recon Automation
Recon("domain"); Performs automated reconnaissance (DNS, subdomains, IP info, ports, headers).

# 12 Web Vulnerability Checks
CheckOpenRedirect("domain"); Simulated open redirect vulnerability check.

# 13 Reporting & Data Management
Export_Report("json|txt"); Exports collected data to a report file.

Export_HTML_Report(); Exports collected data as an HTML report.

ClearReport(); Clears all stored report data.

# NEW COMMANDS AFTER VERSION ALPHA -- 
Web_Fingerprint("example.com");

HTTP_Security_Audit("example.com");

Port_Probe("scanme.nmap.org");

DNS_Intel("example.com");

Password_Leak_Check("password123");

File_Entropy("sample.exe");

Brute_Force_Simulation("admin", 10000);


# Summary
Total commands: 36

Type: Ethical cybersecurity DSL

Platform: Go-based standalone executable

Focus: Reconnaissance, OSINT, analysis, reporting

# Comparison with Python
Python code for Hashing -- import hashlib

h = hashlib.sha256(b"password").hexdigest()

print(h)

Cyber+ Alpha (CPA) command for Hashing --

Hash_Compute("password", "sha256");


# Reports
Cyber+ can automatically generate:

cyber_report.json

cyber_report.html

These contain structured results from executed commands.

# Ethical Disclaimer
Cyber+ is intended only for:

Learning cybersecurity

Defensive security testing

Ethical hacking labs

Awareness & simulation

Do NOT use Cyber+ for illegal activities.
You are responsible for complying with local laws and regulations.


# Contributing
Contributions are welcome!

Create demo .cbp scripts

Open a pull request or start a discussion.

Support the Project
If you find Cyber+ useful:

Star the repository

Report issues

Share with the cybersecurity community

License
MIT License
Free to use for educational and ethical purposes.
