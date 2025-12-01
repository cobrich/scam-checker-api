
---

# 🛡️ Scam Checker API

> **High-performance Threat Intelligence Platform & Phishing Scanner.**
> An open-source alternative to APIVoid, VirusTotal, and URLScan, written in Go.

![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?style=flat&logo=postgresql)
![Redis](https://img.shields.io/badge/Redis-Caching-DC382D?style=flat&logo=redis)
![License](https://img.shields.io/badge/License-MIT-green)

**Scam Checker API** is a robust microservice designed to detect phishing, malware, and scam URLs in real-time. It combines **massive database lookups** (1M+ threats), **advanced heuristic analysis**, and **live infrastructure scanning** to provide a comprehensive risk score.

---

## 🚀 Key Features

### 1. Aggregated Threat Intelligence (7+ Feeds)
Automatically fetches, deduplicates, and updates threat data from the world's best open sources:
*   **PhishTank** (Phishing)
*   **URLhaus** (Malware)
*   **OpenPhish** (Phishing)
*   **ThreatFox** (Botnets & IOCs)
*   **GitHub Phishing Database** (1M+ entries)
*   **VX Vault** (Malware distribution)
*   **Phishing Army** (Phishing)
*   **StopForumSpam** (Toxic Domains)

### 2. Advanced Heuristic Engine (v2)
Uses a weighted scoring system to detect unknown threats based on URL structure:
*   **Typosquatting:** Detects fake brands (e.g., `goggle.com`, `faceb00k.com`) using Levenshtein distance.
*   **Homograph Attacks:** Detects Punycode (`xn--`) and Unicode spoofing.
*   **Obfuscation:** Detects Base64, Hex, and IPFS links.
*   **High Entropy:** Detects DGA (Domain Generation Algorithms).
*   **Semantic Analysis:** Analyzes suspicious keywords (`login`, `secure`, `verify`) in multiple languages (EN, FR, RU).

### 3. Live Infrastructure Scanning
Performs real-time network reconnaissance:
*   **DNS Analysis:** Checks if the domain is alive, has MX records (email), and NS providers.
*   **SSL/TLS Forensics:** Checks certificate validity, issuer, and age. Flags **"Fresh SSL"** (< 24h) and **"Free SSL"** on new domains.
*   **GeoIP & ASN:** Detects hosting provider and country. Flags **"Bulletproof"** hosting and risky jurisdictions.
*   **HTTP Content Scan:** Safely crawls the page to detect password fields, credit card forms, and redirect chains.

### 4. Smart Scoring & Anti-False Positive
*   **Risk Score (0-100):** Calculated using an aggressive weighted formula (Critical/High/Medium/Low).
*   **Anti-FP Logic:** Automatically reduces risk score for:
    *   Old domains (> 1 year).
    *   Trusted Infrastructure (Google, Cloudflare, AWS).
    *   Whitelisted domains.

### 5. High Performance
*   **Redis Caching:** Instant responses for repeated queries.
*   **PostgreSQL Batch Inserts:** Handles massive data ingestion efficiently.
*   **Concurrency:** All checks (DNS, SSL, HTTP) run in parallel.

---

## 🛠️ Tech Stack

*   **Language:** Go (Golang) 1.23
*   **Web Framework:** Fiber (Fast HTTP)
*   **Database:** PostgreSQL (pgx driver)
*   **Cache:** Redis
*   **GeoIP:** MaxMind GeoLite2 (City & ASN)
*   **Deployment:** Docker & Docker Compose

---

## ⚡ Getting Started

### Prerequisites
*   Docker & Docker Compose installed.

### 1. Clone the repository
```bash
git clone https://github.com/cobrich/scam-checker-api.git
cd scam-checker-api
```

### 2. Download GeoIP Databases
Due to licensing, you must download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` from [MaxMind](https://www.maxmind.com) (free account required) and place them in the **root directory** of the project.

### 3. Configuration (Optional)
Create a `.env` file or modify `docker-compose.yml` if needed.
```bash
# Example .env
APP_PORT=:8080
DATABASE_URL=postgres://user:password@db:5432/scam_db
REDIS_URL=redis://redis:6379/0
RUN_FETCHERS=true
# API_SECRET=my_secret_key (Uncomment to enable auth)
```

### 4. Run with Docker
```bash
docker compose up -d --build
```

The API will be available at `http://localhost:8080`.
*Note: The first run will take a few minutes to download and populate the threat database (over 1 million records).*

---

## 📖 API Documentation

### Check a URL

**Endpoint:** `GET /api/check`

**Parameters:**
| Parameter | Type    | Description                                                                                                         |
| :-------- | :------ | :------------------------------------------------------------------------------------------------------------------ |
| `url`     | string  | **Required.** The URL to analyze.                                                                                   |
| `full`    | boolean | `true` to perform live infrastructure scanning (slower ~3-5s, but more detailed). Default: `false` (fast DB check). |

**Example Request:**
```bash
curl "http://localhost:8080/api/check?url=http://secure-login-apple.com&full=true"
```

**Example Response (Dangerous):**
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
    "No HTTPS",
    "Risky Country"
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
    },
    "ssl": null
  }
}
```

### Health Check
**Endpoint:** `GET /health`
```json
{"status": "ok"}
```

---

## ⚙️ Architecture

The system follows a **Smart Pipeline** approach:

1.  **Whitelist Check:** Instant return if domain is trusted (e.g., google.com).
2.  **Database Lookup:** Checks URL hash against local PostgreSQL (1M+ threats).
3.  **Heuristic Analysis:** Analyzes URL string for patterns (Typosquatting, Entropy, etc.).
4.  **Infrastructure Scan (if `full=true`):**
    *   Resolves DNS.
    *   Checks SSL Certificate age.
    *   Checks Hosting Provider (Cloud/Bulletproof).
    *   Scans HTTP content for password fields.
5.  **Scoring & Normalization:** Aggregates all signals, applies Anti-FP logic (e.g., reduces score for old domains), and returns final verdict.

---

## 🛡️ License

This project is licensed under the MIT License.

---

**Developed with ❤️ by cobrich**