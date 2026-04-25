# 🛡️ ThreatView: Project Manifest & Technical Documentation

This document maps the implemented features of the **ThreatView Intelligence Platform** to the requested project phases and technical architecture.

---

## 🏗️ Phase 1: The Ingestion Engine (ETL)
**Goal**: Build a central nervous system for threat data.

- **Data Aggregation**: Modular ingestion service in `backend/services/ingestionService.js` connecting to:
    - **AlienVault OTX**: IP reputation and global pulses.
    - **Shodan**: Vulnerability and service exposure data.
    - **PhishTank**: Real-time phishing URL feeds.
    - **MalwareBazaar**: Recent malware samples and hashes.
- **The Scheduler**: Implemented using `node-cron`. The system performs a full sync every **60 minutes** (configurable in `.env`).
- **Normalization**: Every source is mapped to a unified `ThreatModel` via `SOURCE_FIELD_MAP`, ensuring `src_ip`, `indicator`, and `address` all resolve to a standard schema.

## 📊 Phase 2: The Intelligence Dashboard
**Goal**: Translate raw data into actionable insights.

- **Visualization**: Built with **React** and **Recharts**.
- **Global Threat Map**: A high-fidelity D3-geo visualization that projects threat origin points onto a world map using a precise Mercator projection.
- **Malware Trends**: Dynamic line charts showing ransomware and phishing trends over the last 7 days.
- **Recent IoCs**: A premium, sortable table in the **IoC Search** view with paginated access to the latest indicators.

## 🔍 Phase 3: Actionable Intel (Search & Alerts)
**Goal**: Enable proactive threat hunting and automated response.

- **Searchable IoC Database**: 
    - **Optimized Querying**: Implemented a backend `SearchIndex` for O(1) lookups on exact matches.
    - **Relevance Scoring**: Fuzzy search logic that weights matches based on indicator type and risk.
- **Custom Alerts Engine**:
    - **Logic**: `IF (New_Threat.industry == User.industry) THEN Alert`.
    - **Rules**: Automatic detection of ransomware, critical CVEs, and high-risk geographies.
- **Brand Monitoring**: Specifically monitors incoming phishing feeds for domains impersonating user-tracked brands.
- **Email Notifications**: Full **SendGrid** integration with premium HTML templates.

## 📋 Phase 4: Reporting & Monetization
**Goal**: Deliver value-add features for management and C-suite.

- **PDF Generation**: Powered by **Puppeteer**. Generates a professional "Threat Intelligence Report" featuring executive summaries and high-risk breakdowns.
- **Tiered Access (RBAC)**:
    - **Free Tier**: Limited to a **24-hour data window**.
    - **Pro Tier**: Historical search access, **PDF/CSV/JSON Exports**, and priority alerting.
    - **Enforcement**: Tier gating is enforced at the API level (`x-tier` header validation).

---

## 🛠️ Technical Stack
- **Frontend**: React.js, Framer Motion, Recharts, D3-geo.
- **Backend**: Node.js, Express.
- **Database**: Atomic JSON-based LocalDB (`db.json`) for flexible schema management.
- **Deployment**: Configured for cloud deployment via Environment Variables.

---

## 📖 API Documentation (Standardized)
| Endpoint | Method | Purpose | Tier |
| :--- | :--- | :--- | :--- |
| `/api/indicators` | GET | List/Search threat indicators | Free/Pro |
| `/api/stats` | GET | Dashboard trends and summaries | Free/Pro |
| `/api/export/:type` | GET | Download PDF, CSV, or JSON reports | Pro Only |
| `/api/test/email` | POST | Verify SendGrid integration | Free/Pro |
| `/api/config/status` | GET | System health and mode check | Free/Pro |
