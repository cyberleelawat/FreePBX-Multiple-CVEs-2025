# FreePBX-Multiple-CVEs-2025

This repository documents three security vulnerabilities discovered in FreePBX (CVE-2025-66039, CVE-2025-61678, CVE-2025-61675), including analysis, impact, and proof-of-concept details for security research and awareness purposes.

## Description CVEs
🔴 CVE-2025-61675

A security flaw in FreePBX resulting from improper handling of user-controlled input. This issue may allow an attacker to influence application functionality and potentially impact overall system security.

🔴 CVE-2025-61678

FreePBX contains an input validation vulnerability that may allow attackers to manipulate application behavior. Successful exploitation could affect confidentiality and integrity depending on the attack vector used.

🔴 CVE-2025-66039

This vulnerability in FreePBX is caused by improper access control, allowing an attacker to perform unauthorized actions. Exploitation of this issue can lead to security risks impacting the integrity of the affected FreePBX system.


### This repository contains Nuclei templates for detecting three critical vulnerabilities in FreePBX:

- **CVE-2025-61675**: Authenticated SQL Injection (CVSS 8.6) - Affects endpoint module
- **CVE-2025-61678**: Authenticated Arbitrary File Upload (CVSS 8.6) - Affects endpoint module
- **CVE-2025-66039**: Authentication Bypass (CVSS 9.3) - Affects framework module

## <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Objects/Package.png" alt="Package" width="25" height="25" /> Affected Versions

### CVE-2025-61675 & CVE-2025-61678 (endpoint module)
- **FreePBX 16**: < 16.0.92 (patched in 16.0.92)
- **FreePBX 17**: < 17.0.6 (patched in 17.0.6)

### CVE-2025-66039 (framework module)
- **FreePBX 16**: < 16.0.44 (patched in 16.0.44)
- **FreePBX 17**: < 17.0.23 (patched in 17.0.23)

## <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Objects/Magnifying%20Glass%20Tilted%20Left.png" alt="Search" width="25" height="25" /> How does this detection method work?

These templates detect vulnerable FreePBX instances by:
1. Extracting the FreePBX version from the administration panel
2. Comparing the version against known vulnerable version ranges
3. Confirming the presence of FreePBX-specific identifiers

The detection is non-invasive and does not attempt to exploit the vulnerabilities.

## Search Dorks for Identifying Vulnerable FreePBX Instances
#### all CVEs Shodan and hunter dorks

##### Shodan
```
http.title:"FreePBX Administration"
```

##### Hunter
```
product.name="FreePBX Console"
```

#### 🔴 CVE-2025-66039 – FreePBX (Improper Access Control)
🌐 Google Dorks
```
intitle:"FreePBX Administration"
"FreePBX" "Administration"
inurl:/admin/config.php "FreePBX"
```

🔍 Shodan
```
http.title:"FreePBX"
http.html:"FreePBX Administration"
product:"FreePBX"
```

🛰️ FOFA
```
title="FreePBX"
body="FreePBX Administration"
app="FreePBX"
```

👁️ ZoomEye
```
app:"FreePBX"
title:"FreePBX"
```

#### 🔴 CVE-2025-61678 – FreePBX (Input Validation Issue)
🌐 Google Dorks
```
"FreePBX" "User Control Panel"
inurl:/ucp/login
"FreePBX" "UCP"
```

🔍 Shodan
```
http.html:"User Control Panel"
http.html:"FreePBX"
```

🛰️ FOFA
```
body="User Control Panel"
body="FreePBX"
```

👁️ ZoomEye
```
app:"FreePBX"
body:"User Control Panel"
```

#### 🔴 CVE-2025-61675 – FreePBX (User Input Handling)
🌐 Google Dorks
```
inurl:/admin "FreePBX"
inurl:/recordings "FreePBX"
"FreePBX" "Dashboard"
```

🔍 Shodan
```
http.html:"FreePBX Dashboard"
http.favicon.hash:-1238045827
```

🛰️ FOFA
```
body="FreePBX Dashboard"
icon_hash="-1238045827"
```

👁️ ZoomEye
```
app:"FreePBX"
body:"Dashboard"
```

## <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Travel%20and%20places/Rocket.png" alt="Rocket" width="25" height="25" /> How do I run this script?

#### Installation (One Command!)

```
git clone https://github.com/cyberleelawat/FreePBX-Multiple-CVEs-2025.git
cd FreePBX-Multiple-CVEs-2025
```

#### Authenticated SQL Injection 

```
nuclei -u https://example.com -t CVE-2025-61675.yaml
```
#### Check multiple domain and Subdomain
```
nuclei -l subdomain.txt -t CVE-2025-61675.yaml
```

#### Authenticated Arbitrary File Upload
```sh
nuclei -u https://example.com -t CVE-2025-61678.yaml
```
#### Check multiple domain and Subdomain
```
nuclei -l subdomain.txt -t CVE-2025-61678.yaml
```

#### Authentication Bypass Check
```sh
nuclei -u https://example.com -t CVE-2025-66039.yaml
```
#### Check multiple domain and Subdomain
```
nuclei -l subdomain.txt -t CVE-2025-66039.yaml
```
### Example Output

```
[CVE-2025-61675] [http] [high] FreePBX Authenticated SQL Injection
[CVE-2025-61678] [http] [high] FreePBX Authenticated Arbitrary File Upload
[CVE-2025-66039] [http] [critical] FreePBX Authentication Bypass
```

## <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Objects/Books.png" alt="Books" width="25" height="25" /> References

- [CVE-2025-61675 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-61675)
- [CVE-2025-61678 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-61678)
- [CVE-2025-66039 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-66039)
- [Nuclei - ProjectDiscovery](https://github.com/projectdiscovery/nuclei)


## <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Symbols/Warning.png" alt="Warning" width="25" height="25" /> Disclaimer

Use at your own risk, I will not be responsible for illegal activities you conduct on infrastructure you do not own or have permission to scan.

---

#### Create By : **Virendra Kumar**
#### Organization : **Cyber Leelawat**
#### Website : https://cyberleelawat.vercel.app
