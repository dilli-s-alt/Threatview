# ThreatView Intelligence Platform

A tiered threat intelligence dashboard for SMBs.

## Architecture
- **Backend**: Node.js / Express (Deployed on Render: https://threatview-ayee.onrender.com)
- **Frontend**: React / Vite (Deployed on Vercel: https://threatview-lake.vercel.app)

## Deployment Config
### Backend (Render)
- **Root Directory**: `backend`
- **Build Command**: `npm install`
- **Start Command**: `node src/index.js`
- **Environment Variables**:
  - `PORT`: 10000 (standard for Render)
  - `NODE_ENV`: production
  - `VERBOSE_LOGS`: false
  - `ALIENVAULT_API_KEY`: [YOUR_KEY]
  - `SHODAN_API_KEY`: [YOUR_KEY]
  - `SENDGRID_API_KEY`: [YOUR_KEY]
  - `SENDGRID_FROM_EMAIL`: [YOUR_VERIFIED_EMAIL]

### Frontend (Vercel)
- **Root Directory**: `frontend`
- **Build Command**: `npm run build`
- **Output Directory**: `dist`
- **Environment Variables**:
  - `VITE_API_BASE`: https://threatview-ayee.onrender.com
