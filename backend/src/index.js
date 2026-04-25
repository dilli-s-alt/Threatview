require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const { initScheduler } = require('../services/ingestionService');
const apiRoutes = require('../routes/api');
const app = express();
const PORT = process.env.PORT || 3001;
const VERBOSE_LOGS = process.env.VERBOSE_LOGS === 'true';
app.use(helmet({
  contentSecurityPolicy: false,
}));
app.use(cors());
if (VERBOSE_LOGS) {
  app.use(morgan('dev'));
}
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
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`✅ Backend listening on http://0.0.0.0:${PORT}`);
      
      // Initialize scheduler after port is open to prevent blocking startup
      initScheduler();
      if (VERBOSE_LOGS) {
        console.log('✅ Ingestion scheduler initialized');
        console.log(`   API Docs: http://127.0.0.1:${PORT}/api/docs`);
        console.log(`   Health: http://127.0.0.1:${PORT}/health`);
        console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
        console.log(`   Scheduler: ${process.env.ENABLE_SCHEDULED_INGESTION !== 'false' ? 'ENABLED' : 'DISABLED'}`);
        console.log(`   Email Alerts: ${process.env.ENABLE_EMAIL_ALERTS !== 'false' ? 'ENABLED' : 'DISABLED'}`);
      }
    });

    server.on('error', (e) => {
      if (e.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use. Please kill any existing processes on this port.`);
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