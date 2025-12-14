# CVE-2025-55182 Advanced Scanner 🚀
![IMG_20251214_204122](https://github.com/user-attachments/assets/0592ea6f-0799-4c2a-ac35-a1dc2e63afe4)
![Bash](https://img.shields.io/badge/Bash-Script-green)
![Security](https://img.shields.io/badge/Security-CVE--Scanner-red)
![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-orange)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![License](https://img.shields.io/badge/License-Educational-blue)

A **professional and automated security scanner** to detect and validate **CVE-2025-55182**, a critical vulnerability affecting **Next.js (React Server Components)**.

Designed for **security researchers, penetration testers, and bug bounty hunters** who want fast, clean, and reliable vulnerability verification.

---

## ✨ Features
- 🔍 Automated detection of CVE-2025-55182
- ⚡ Fast & lightweight Bash-based tool
- 🎯 Custom command execution support
- 📦 Inspired by ProjectDiscovery Nuclei template
- 🧠 Clean decoded output
- 🛡️ Smart error handling (403, WAF, SSL, timeout)

---

## 🧩 Vulnerability Overview
- **CVE ID:** CVE-2025-55182  
- **Category:** Remote Code Execution (RCE)  
- **Affected Tech:** Next.js – React Server Components  
- **Impact:** Arbitrary command execution on the server  

This vulnerability occurs due to **improper handling of internal RSC requests and prototype manipulation**, which can allow attackers to execute system-level commands.

🔗 **CVE Reference:**  
- https://nvd.nist.gov/vuln/detail/CVE-2025-55182  
- https://cloud.projectdiscovery.io/library/CVE-2025-55182  

> ⚠️ Test **only on assets you own or have explicit permission for**.

---

## 📂 Requirements
- Linux / macOS
- `bash`
- `curl`
- `openssl`
- `python3` (optional, recommended)

---

## 🚀 Installation
```bash
git clone https://github.com/CyberPrince-hub/CVE-2025-55182-Advanced-Scanner.git
cd CVE-2025-55182-Advanced-Scanner
chmod +x scanner.sh

---

## ⚡Usage 
./scanner.sh -d <target> -c <command>
---
## 🔥 Examples 

./scanner.sh -d vulnapp.com -c id
./scanner.sh -d http://localhost:3000 -c "ping -c 3 google.com"
./scanner.sh -d vulnapp.com -c "cat /etc/passwd"


⚠️ Disclaimer

This project is intended strictly for educational and authorized security testing.

❌ Unauthorized testing is illegal.
The author takes no responsibility for misuse or damage.


---

👨‍💻 Author

Prince Roy
Bug Bounty Hunter | Cybersecurity Learner

📌 LinkedIn / GitHub: (add your profile link here)


---

⭐ Support & Contribution

If this project helped you:

⭐ Star the repository

🍴 Fork and improve it

🐞 Submit issues or PRs




