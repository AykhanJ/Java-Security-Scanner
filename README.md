# 🔐 Security Scanner
 
A desktop application built with **Java + JavaFX** that scans websites and hosts for common security vulnerabilities — including missing HTTP headers, open ports, and weak SSL/TLS configurations. Results are persisted in a local database and can be exported as a PDF report.
 
---
 
## 📸 Features
 
### 🛡️ HTTP Security Header Scanner
Connects to a target URL and checks for the presence of critical security headers:
 
| Header | Severity |
|---|---|
| `Strict-Transport-Security` | HIGH |
| `Content-Security-Policy` | HIGH |
| `X-Frame-Options` | MEDIUM |
| `X-Content-Type-Options` | MEDIUM |
| `X-XSS-Protection` | MEDIUM |
| `Permissions-Policy` | MEDIUM |
| `Referrer-Policy` | LOW |
| `Cache-Control` | LOW |
 
Also detects **server version disclosure** (`Server` header) and **technology disclosure** (`X-Powered-By` header).
 
### 🔌 Port Scanner
Multi-threaded port scanner with a configurable port range. Identifies open ports and maps them to known services:
 
`FTP` · `SSH` · `Telnet` · `SMTP` · `DNS` · `HTTP` · `HTTPS` · `MySQL` · `PostgreSQL` · `MSSQL` · `RDP` and more.
 
### 🔒 SSL/TLS Scanner
Analyzes the SSL/TLS configuration of a target host and flags:
- Weak/deprecated protocols: `SSLv2`, `SSLv3`, `TLSv1`, `TLSv1.1`
- Weak cipher suites (RC4, DES, MD5-based, EXPORT ciphers)
- Certificate expiry and validity issues
### 📊 Results & Reporting
- All scan results are displayed in a sortable table with severity levels (HIGH / MEDIUM / LOW / INFO)
- Scan history is persisted in a local **H2 embedded database**
- Results can be **exported to a PDF report** via Apache PDFBox
---
 
## 🛠️ Tech Stack
 
| Technology | Purpose |
|---|---|
| Java 17 | Core language |
| JavaFX 17.0.2 | Desktop GUI |
| Maven | Build & dependency management |
| H2 Database | Local scan history persistence |
| BouncyCastle (`bcpkix`) | SSL/TLS certificate analysis |
| Apache PDFBox | PDF report generation |
| JUnit Jupiter 5 | Unit testing |
 
---
 
## 🚀 Getting Started
 
### Prerequisites
 
- **JDK 17+** — [Download here](https://adoptium.net/)
- **Maven 3.6+** — [Download here](https://maven.apache.org/download.cgi)
### Clone the Repository
 
```bash
git clone https://github.com/your-username/security-scanner.git
cd security-scanner/security-scanner
```
 
### Run the Application
 
```bash
mvn exec:java
```
 
> **Note:** On first run, Maven will download all dependencies automatically. An internet connection is required.
 
### Build a JAR
 
```bash
mvn package
```
 
The compiled JAR will be at `target/security-scanner-1.0-SNAPSHOT.jar`.
 
---
 
## 🖥️ Opening in Eclipse IDE
 
> ⚠️ **Important:** Import the inner `security-scanner/` folder, **not** the outer `Java Project/` folder.
 
1. Open Eclipse (IDE for Java Developers, 2022-06 or newer)
2. Make sure **JDK 17** is configured: `Window → Preferences → Java → Installed JREs`
3. Go to `File → Import → Maven → Existing Maven Projects → Next`
4. Set **Root Directory** to the `security-scanner/` subfolder
5. Check the `pom.xml` entry → **Finish**
6. Wait for Maven to resolve dependencies
7. Right-click `Main.java` → **Run As → Java Application**
---
 
## 📁 Project Structure
 
```
security-scanner/
├── src/
│   ├── main/
│   │   ├── java/com/securityscanner/
│   │   │   ├── Main.java                  # Entry point
│   │   │   ├── SecurityScannerApp.java    # JavaFX UI
│   │   │   ├── model/
│   │   │   │   └── SecurityIssue.java     # Data model
│   │   │   └── service/
│   │   │       ├── HeaderScanner.java     # HTTP header checks
│   │   │       ├── PortScanner.java       # Multi-threaded port scan
│   │   │       ├── SSLScanner.java        # SSL/TLS analysis
│   │   │       └── DatabaseManager.java   # H2 persistence layer
│   │   └── resources/
│   │       ├── logo.png
│   │       └── shield.png
│   └── test/
│       └── java/com/securityscanner/
│           └── AppTest.java
└── pom.xml
```
 
---
 
## ⚠️ Disclaimer
 
This tool is intended for **educational and authorized security testing only**. Do not scan hosts or networks without explicit permission from the owner. The author is not responsible for any misuse.
 
---
 
## 📄 License
 
This project is open source and available under the [MIT License](LICENSE).
