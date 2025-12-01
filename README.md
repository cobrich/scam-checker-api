
---

# 🛡️ Scam Checker API

> High-performance, open-source Threat Intelligence Platform & Phishing Scanner written in Go.
> An alternative to APIVoid, VirusTotal, and URLScan.

![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker)
![License](https://img.shields.io/badge/License-MIT-green)

**Scam Checker API** is a powerful microservice that analyzes URLs for phishing, malware, and scam indicators using a hybrid approach: **Database Lookups + Heuristic Analysis + Live Infrastructure Scanning**.

---

## 🚀 Features

### 1. Threat Intelligence Aggregation (Database)
Automatically fetches and updates threat feeds from 7+ sources:
*   **PhishTank** (Phishing)
*   **URLhaus** (Malware)
*   **OpenPhish** (Phishing)
*   **ThreatFox** (Botnets)
*   **GitHub Phishing Database** (Aggregated)
*   **VX Vault** (Malware)
*   **Phishing Army** (Phishing)

### 2. Advanced Heuristics (Static Analysis)
Analyzes the URL string structure to detect unknown threats:
*   **Typosquatting:** Detects fake brands (e.g., `goggle.com`, `faceb00k.com`) using Levenshtein distance.
*   **Homograph Attacks:** Detects Punycode (`xn--`) and Unicode spoofing.
*   **Obfuscation:** Detects Base64, Hex, and IPFS links.
*   **High Entropy:** Detects DGA (Domain Generation Algorithms).
*   **Keywords:** Analyzes suspicious words (`login`, `secure`, `verify`) in multiple languages.

### 3. Live Infrastructure Scanning
Performs real-time network checks:
*   **DNS:** Checks if the domain is alive, has MX records (email), and NS providers.
*   **SSL/TLS:** Checks certificate validity, issuer, and age (e.g., "Fresh SSL" < 24h).
*   **GeoIP & ASN:** Detects hosting provider and country. Flags "Bulletproof" hosting and risky countries.
*   **HTTP Analysis:** Crawls the page (safely) to detect password fields, credit card forms, and redirect chains.

### 4. Smart Scoring Engine
*   Calculates a **Risk Score (0-100)** based on weighted rules.
*   **Anti-False Positive Logic:** Reduces score for old domains (> 1 year) and trusted infrastructure (Google, Cloudflare).

---

## 🛠️ Tech Stack

*   **Language:** Go (Golang) 1.23+
*   **Framework:** Fiber (Fast HTTP)
*   **Database:** PostgreSQL (pgx driver)
*   **Deployment:** Docker & Docker Compose
*   **GeoIP:** MaxMind GeoLite2 (City & ASN)

---

## ⚡ Quick Start

### Prerequisites
*   Docker & Docker Compose

### 1. Clone the repository
```bash
git clone https://github.com/cobrich/scam-checker-api.git
cd scam-checker-api
```

### 2. Download GeoIP Databases
Due to licensing, you must download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` from [MaxMind](https://www.maxmind.com) and place them in the root directory.

### 3. Run with Docker
```bash
docker compose up -d --build
```

The API will be available at `http://localhost:8080`.
*Note: The first run will take a few minutes to download and populate the threat database.*

---

## 📖 API Usage

### Check a URL

**Endpoint:** `GET /api/check`

**Parameters:**
*   `url` (required): The URL to analyze.
*   `full` (optional): `true` to perform live infrastructure scanning (slower but more detailed).

**Example Request:**
```bash
curl "http://localhost:8080/api/check?url=http://secure-login-apple.com&full=true"
```

**Example Response:**
```json
{
  "target": "http://secure-login-apple.com",
  "verdict": "Dangerous",
  "risk_score": 100,
  "reason": "Suspicious Activity Detected",
  "summary": {
    "critical": 2,
    "high": 1,
    "medium": 0,
    "low": 1
  },
  "signals": [
    "Typosquatting",
    "Brand Injection",
    "No HTTPS"
  ],
  "heuristics": [
    {
      "name": "Typosquatting",
      "desc": "Token 'apple' ~ 'apple'",
      "score": 55
    },
    {
      "name": "Brand Injection",
      "desc": "Brand 'apple' injected into domain",
      "score": 40
    }
  ],
  "infrastructure": {
    "status": "Online",
    "ip": "1.2.3.4",
    "geolocation": {
      "country": "China",
      "isp": "Unknown Host"
    }
  }
}
```

### Health Check
**Endpoint:** `GET /health`
```json
{"status": "ok"}
```

---

## ⚙️ Configuration

Configure the application via `.env` or `docker-compose.yml`:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `APP_PORT` | Port to listen on | `:8080` |
| `DATABASE_URL` | PostgreSQL connection string | `postgres://...` |
| `RUN_FETCHERS` | Enable background threat feed updates | `true` |
| `API_SECRET` | (Optional) Protect API with a key | - |

---

## 🛡️ License

This project is licensed under the MIT License.

---

**Developed with ❤️ by cobrich**