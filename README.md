# 🛡️ ThreatView: Security Intelligence Platform for SMBs

**ThreatView** is a central nervous system for threat data, designed to translate noisy, raw indicators from multiple sources into actionable security insights for IT managers.

---

## 🚀 Key Deliverables

### 1. Modular Repository Architecture
The project follows a strict separation of concerns:
- **`backend/services/ingestionService.js`**: The **ETL Engine**. Handles all external API logic, rate limiting, and data normalization.
- **`backend/routes/api.js`**: The **Dashboard API**. Serves aggregated stats, trends, and search results to the frontend.
- **`backend/models/`**: Defines the unified `ThreatModel` used across all feeds.
- **`frontend/src/`**: A high-fidelity React application utilizing D3-geo and Recharts for premium data visualization.

### 2. Scheduled Intelligence Updates
- **Frequency**: The system is configured to perform a full global sync **every 60 minutes**.
- **Implementation**: Powered by `node-cron`, the scheduler triggers a cascaded ingestion from all integrated feeds, followed by automatic data rotation (purging data older than 7 days to maintain performance).
- **Latency**: The dashboard displays real-time data from the current day, verifying the scheduler's health.

### 3. Integrated Threat Feeds
ThreatView aggregates intelligence from the following world-class open-source providers:
- **AlienVault OTX**: Integrated for global IP reputation and pulse-based threat indicators.
- **Shodan**: Used to identify vulnerable services and exposed ports across mapped IPs.
- **PhishTank**: Integrated for real-time URL-based phishing intelligence and brand impersonation monitoring.
- **MalwareBazaar**: Provides the latest malware file hashes and family classifications.

---

## 🏗️ Technical Architecture & Features

### 🔍 Actionable Intelligence
- **O(1) Search Indexing**: Instant lookups for suspicious IPs or domains.
- **Rule-Based Alerting**: Custom logic engine triggers high-priority alerts when threats match your industry profile (e.g., Healthcare).
- **Brand Monitoring**: Proactive detection of domain name squatting and brand phishing.

### 📊 Advanced Visualization
- **Attack Source Map**: Precise D3-geo Mercator projection of threat origins.
- **Trend Analysis**: 7-day trend tracking for Ransomware, Phishing, and Malware variants.

### 📋 Enterprise Reporting (Pro)
- **PDF Generation**: High-fidelity Puppeteer-generated reports for C-Suite presentations.
- **RBAC Gating**: Tiered access levels enforcing a 24-hour window for free users and unlimited history for Pro users.

---

## 🛠️ Getting Started

### Prerequisites
- Node.js v18+
- API Keys for AlienVault and Shodan (optional, mock mode provided)

### Installation
1. Clone the repository.
2. Run `npm install` in both `/frontend` and `/backend` directories.
3. Configure your `.env` file in the `/backend` folder.
4. Start the services:
   - Backend: `npm run dev` (Port 3001)
   - Frontend: `npm run dev` (Port 5173)

---

## ☁️ Deployment Guide
ThreatView is optimized for containerized deployment (Docker) or traditional cloud hosting:
- **Backend**: Can be deployed to Heroku, Render, or AWS EC2.
- **Frontend**: Optimized for Vercel, Netlify, or AWS S3+CloudFront.
- **Persistence**: Uses a portable `db.json` structure, allowing for easy backup and migration without heavy DB infrastructure.

---
© 2026 ThreatView Intelligence Platform | Security Software Engineer Intern Deliverable
