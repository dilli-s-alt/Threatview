require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const { initScheduler } = require('./services/ingestionService');
const apiRoutes = require('./routes/api');
const app = express();
const PORT = process.env.PORT || 3001;
const VERBOSE_LOGS = process.env.VERBOSE_LOGS === 'true';

const REQUIRED_ENV = ['ALIENVAULT_API_KEY', 'SENDGRID_API_KEY', 'SENDGRID_FROM_EMAIL'];
REQUIRED_ENV.forEach(key => {
  if (!process.env[key]) {
    console.warn(`⚠️  WARNING: Missing environment variable: ${key}`);
  }
});
app.use(helmet({
  contentSecurityPolicy: false,
}));
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-tier', 'x-user-id']
}));

if (VERBOSE_LOGS) {
  app.use(morgan('dev'));
}

app.get('/', (req, res) => {
  res.json({ 
    message: 'ThreatView API is Online', 
    docs: '/api/docs',
    health: '/health',
    timestamp: new Date().toISOString() 
  });
});

app.use(express.json());
app.use('/api', apiRoutes);

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});
app.get('/api/docs', (req, res) => {
  res.json({
    service: 'ThreatView Intelligence API',
    version: '1.0.0',
    endpoints: {
      'Dashboard': {
        'GET /api/stats': 'Dashboard statistics (indicators, trends, top countries)',
        'GET /api/indicators/stats/detailed': 'Detailed breakdown by type, source, threat'
      },
      'Search & Indicators': {
        'GET /api/indicators': 'Search indicators with pagination (query: page, limit, search, type)',
        'GET /api/indicators/:id': 'Get single indicator',
        'GET /api/search': 'Lookup an IoC or threat keyword (query: query)',
        'GET /api/brand/search': 'Brand monitoring (query: domain)'
      },
      'Alerts': {
        'GET /api/alerts': 'Get user alerts (header: x-user-id)',
        'PUT /api/alerts/:alertId/acknowledge': 'Mark alert as acknowledged'
      },
      'Visualization': {
        'GET /api/stats/overview': 'High-level dashboard totals',
        'GET /api/stats/trends': 'Detection and ransomware trend series',
        'GET /api/stats/geo': 'Geospatial threat distribution for attack map'
      },
      'Reports': {
        'GET /api/reports/download/pdf': 'Download PDF report (header: x-tier=pro)',
        'GET /api/reports/download/csv': 'Download CSV export (header: x-tier=pro)',
        'GET /api/reports/download/json': 'Download JSON export (header: x-tier=pro)'
      },
      'Ingestion': {
        'POST /api/ingestion/manual-sync': 'Trigger manual data sync',
        'GET /api/ingestion/status': 'Get pipeline status'
      },
      'Subscriptions': {
        'POST /api/subscriptions': 'Create subscription',
        'GET /api/subscriptions': 'Get all subscriptions'
      }
    },
    headers: {
      'x-tier': 'free or pro (for tiered features)',
      'x-user-id': 'user identifier (for alerts)'
    }
  });
});
const startServer = async () => {
  try {
    const server = app.listen(PORT, () => {
      console.log(`✅ Backend listening on port ${PORT}`);
      
      initScheduler();
      
      const Indicator = require('./models/Indicator');
      Indicator.count().then(count => {
        if (count === 0) {
          console.log('🗂️  Database empty, triggering initial ingestion...');
          const { runFullSyncCycle } = require('./services/ingestionService');
          runFullSyncCycle().catch(err => console.error('❌ Initial sync failed:', err));
        }
      });
    });

    server.on('error', (e) => {
      if (e.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use.`);
        process.exit(1);
      } else {
        console.error('❌ Server error:', e);
      }
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};
startServer();
