const express = require('express');
const router = express.Router();
const Indicator = require('../models/Indicator');
const {
  checkAlerts,
  getAlertStats,
  getUserAlerts,
  acknowledgeAlert
} = require('../services/alertService');
const {
  generateThreatReport,
  generateCSVExport,
  generateJSONExport
} = require('../services/reportingService');
const { runFullSyncCycle } = require('../services/ingestionService');
const EmailService = require('../services/emailService');
const db = require('../database');
const formatDateKey = (value) => {
  const date = new Date(value || new Date());
  return date.toISOString().split('T')[0];
};
const buildTrendSeries = (items, days = 7) => {
  const today = new Date();
  return Array.from({ length: days }).map((_, idx) => {
    const current = new Date(today);
    current.setDate(today.getDate() - (days - idx - 1));
    const dayKey = current.toISOString().split('T')[0];
    return { date: dayKey, count: 0 }; // Return empty data or remove usage
  });
};
const buildCountryDistribution = (indicators, limit = 10) => {
  const byCountry = indicators.reduce((acc, indicator) => {
    const country = (indicator.country || 'Unknown').toUpperCase();
    acc[country] = (acc[country] || 0) + 1;
    return acc;
  }, {});
  return Object.entries(byCountry)
    .map(([country, count]) => ({ country, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
};
const COUNTRY_COORDINATES = {
  US: { latitude: 39, longitude: -98 },
  CN: { latitude: 35, longitude: 103 },
  RU: { latitude: 55, longitude: 37 },
  IN: { latitude: 22, longitude: 78 },
  BR: { latitude: -10, longitude: -51 },
  DE: { latitude: 51, longitude: 10 },
  FR: { latitude: 46, longitude: 2 },
  GB: { latitude: 54, longitude: -1 },
  JP: { latitude: 36, longitude: 138 },
  KR: { latitude: 37, longitude: 127 },
  CA: { latitude: 56, longitude: -106 }
};
const attachCountryCoordinates = (distribution) => distribution.map(item => ({
  ...item,
  latitude: COUNTRY_COORDINATES[item.country]?.latitude || null,
  longitude: COUNTRY_COORDINATES[item.country]?.longitude || null
}));
const normalizeDomain = (value) => {
  if (!value) return '';
  return value
    .toString()
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/\/.*$/, '');
};
const resolveMatchType = (indicator, domain) => {
  const normalizedIndicator = (indicator || '').toLowerCase();
  const normalizedDomain = normalizeDomain(domain);
  if (normalizedIndicator === normalizedDomain) return 'exact';
  if (normalizedIndicator.includes(`.${normalizedDomain}`)) return 'subdomain';
  if (normalizedIndicator.includes(normalizedDomain)) return 'contains';
  return 'partial';
};
const matchBrandIndicator = (indicator, domain) => {
  const normalizedIndicator = (indicator || '').toLowerCase();
  const normalizedDomain = normalizeDomain(domain);
  if (!normalizedIndicator || !normalizedDomain) return false;
  return normalizedIndicator === normalizedDomain
    || normalizedIndicator.includes(`.${normalizedDomain}`)
    || normalizedIndicator.includes(normalizedDomain);
};
const parseSearchQuery = (query) => {
  const tokens = (query || '').match(/"[^"]+"|\S+/g) || [];
  const filters = {};
  const terms = [];
  tokens.forEach((token) => {
    const cleanToken = token.replace(/^"|"$/g, '').trim();
    if (!cleanToken) return;
    const [key, ...rest] = cleanToken.split(':');
    const value = rest.join(':').trim();
    if (['type', 'source', 'country', 'threat', 'indicator', 'risk'].includes(key.toLowerCase()) && value) {
      filters[key.toLowerCase()] = value;
    } else {
      terms.push(cleanToken.toLowerCase());
    }
  });
  return { filters, terms };
};
const parseRiskFilter = (value) => {
  const normalized = value.replace(/\s+/g, '');
  if (/^>=?\d{1,3}$/.test(normalized)) {
    return { op: normalized.startsWith('>=') ? '>=' : '>', value: parseInt(normalized.replace(/[^0-9]/g, ''), 10) };
  }
  if (/^<=?\d{1,3}$/.test(normalized)) {
    return { op: normalized.startsWith('<=') ? '<=' : '<', value: parseInt(normalized.replace(/[^0-9]/g, ''), 10) };
  }
  if (/^\d{1,3}-\d{1,3}$/.test(normalized)) {
    const [min, max] = normalized.split('-').map(v => parseInt(v, 10));
    return { op: 'range', min, max };
  }
  const asInt = parseInt(normalized, 10);
  if (!Number.isNaN(asInt)) return { op: '==', value: asInt };
  return null;
};
class SearchIndex {
  constructor() {
    this.exactMap = new Map();
    this.isBuilt = false;
  }
  build(indicators) {
    this.exactMap.clear();
    indicators.forEach(item => {
      if (item.indicator) this.exactMap.set(item.indicator.toLowerCase(), item);
    });
    this.isBuilt = true;
  }
  lookup(indicator) {
    return this.exactMap.get(indicator.toLowerCase());
  }
}
const searchIndex = new SearchIndex();

const matchFilters = (item, filters) => {
  const indicator = (item.indicator || '').toLowerCase();
  const type = (item.type || '').toLowerCase();
  const threatType = (item.threat_type || '').toLowerCase();
  const source = (item.source || '').toLowerCase();
  const country = (item.country || '').toLowerCase();
  const tags = ((item.metadata || {}).tags || []).join(' ').toLowerCase();
  const score = Number(item.risk_score || 0);
  if (filters.type && !type.includes(filters.type.toLowerCase())) return false;
  if (filters.source && !source.includes(filters.source.toLowerCase())) return false;
  if (filters.country && !country.includes(filters.country.toLowerCase())) return false;
  if (filters.threat && !threatType.includes(filters.threat.toLowerCase())) return false;
  if (filters.indicator && !indicator.includes(filters.indicator.toLowerCase())) return false;
  if (filters.risk) {
    const rule = parseRiskFilter(filters.risk);
    if (rule) {
      if (rule.op === '>=' && score < rule.value) return false;
      if (rule.op === '>' && score <= rule.value) return false;
      if (rule.op === '<=' && score > rule.value) return false;
      if (rule.op === '<' && score >= rule.value) return false;
      if (rule.op === '==' && score !== rule.value) return false;
      if (rule.op === 'range' && (score < rule.min || score > rule.max)) return false;
    }
  }
  return true;
};
const searchIndicators = (indicators, query, isPro) => {
  const q = (query || '').trim();
  if (!q) return indicators;
  if (!searchIndex.isBuilt) searchIndex.build(indicators);
  const { filters, terms } = parseSearchQuery(q);
  if (terms.length === 1 && Object.keys(filters).length === 0) {
    const exact = searchIndex.lookup(terms[0]);
    if (exact) return [{ ...exact, _score: 200 }];
  }
  return indicators
    .map((item) => {
      let score = 0;
      const indicator = (item.indicator || '').toLowerCase();
      const type = (item.type || '').toLowerCase();
      const threatType = (item.threat_type || '').toLowerCase();
      const source = (item.source || '').toLowerCase();
      const country = (item.country || '').toLowerCase();
      const tags = ((item.metadata || {}).tags || []).join(' ').toLowerCase();
      const rawString = `${indicator} ${type} ${threatType} ${source} ${country} ${tags}`;
      if (!matchFilters(item, filters)) return null;
      terms.forEach((term) => {
        if (indicator === term) score += 100;
        else if (indicator.includes(term)) score += 60;
        if (threatType === term) score += 40;
        else if (threatType.includes(term)) score += 25;
        if (type === term) score += 30;
        if (source === term) score += 20;
        if (country === term) score += 10;
        if (tags.includes(term)) score += 12;
        if (rawString.includes(term)) score += 5;
      });
      if (filters.risk) {
        const rule = parseRiskFilter(filters.risk);
        if (rule) {
          const value = Number(item.risk_score || 0);
          if (rule.op === '>=' && value >= rule.value) score += 25;
          if (rule.op === '>' && value > rule.value) score += 20;
          if (rule.op === '<=' && value <= rule.value) score += 25;
          if (rule.op === '<' && value < rule.value) score += 20;
          if (rule.op === '==' && value === rule.value) score += 30;
          if (rule.op === 'range' && value >= rule.min && value <= rule.max) score += 30;
        }
      }
      return { ...item, _score: score };
    })
    .filter((item) => item && item._score > 0)
    .sort((a, b) => b._score - a._score);
};
const isProTier = (req) => (req.headers['x-tier'] || 'free').toString().toLowerCase() === 'pro';
const filterByTier = (indicators, isPro) => {
  if (isPro) return indicators;
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
  return indicators.filter(i => new Date(i.last_seen || i.createdAt) >= cutoff);
};
router.get('/config/status', (req, res) => {
  res.json({
    emailService: EmailService.mockMode ? 'mock' : 'live',
    ingestion: process.env.ENABLE_SCHEDULED_INGESTION === 'true' ? 'enabled' : 'disabled',
    database: 'healthy',
    timestamp: new Date().toISOString()
  });
});
router.post('/test/email', async (req, res) => {
  try {
    const tier = req.headers['x-tier'] || 'free';
    const user = { name: 'Demo User', email: 'demo@threatview.com', tier };
    const mockIndicator = { indicator: '1.2.3.4', type: 'ip', threat_type: 'Test Alert', risk_score: 85, source: 'System Test', country: 'US' };
    const result = await EmailService.sendAlertNotification(user, mockIndicator, 'This is a test alert to verify your SendGrid integration.');
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
router.get('/stats', async (req, res) => {
  try {
    const isPro = isProTier(req);
    const indicators = await Indicator.findAll();
    const indicatorsWindow = filterByTier(indicators, isPro);
    const stats = await Indicator.getStats();
    const alertStats = await getAlertStats();
    const typeDistribution = Object.entries(
      indicatorsWindow.reduce((acc, item) => {
        const type = item.type || 'unknown';
        acc[type] = (acc[type] || 0) + 1;
        return acc;
      }, {})
    ).map(([type, count]) => ({ name: type.toUpperCase(), value: count }));
    const countryDistribution = Object.entries(
      indicatorsWindow.reduce((acc, item) => {
        const country = (item.country || 'Unknown').toUpperCase();
        acc[country] = (acc[country] || 0) + 1;
        return acc;
      }, {})
    )
      .map(([country, count]) => ({ country, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
    const riskCounts = indicatorsWindow.reduce((acc, item) => {
      const level = (item.risk_level || 'low').toLowerCase();
      if (!acc[level]) acc[level] = 0;
      acc[level] += 1;
      return acc;
    }, { high: 0, medium: 0, low: 0 });
    const uniqueSources = new Set(indicatorsWindow.map(i => (i.source || 'unknown').toLowerCase()));
    const uniqueCountries = new Set(indicatorsWindow.map(i => (i.country || 'Unknown').toUpperCase()));
    res.json({
      totalIndicators: indicatorsWindow.length,
      highRiskCount: riskCounts.high,
      mediumRiskCount: riskCounts.medium,
      lowRiskCount: riskCounts.low,
      sourceCount: uniqueSources.size,
      countryCount: uniqueCountries.size,
      typeDistribution,
      countryDistribution,
      mapPoints: attachCountryCoordinates(countryDistribution.slice(0, 8)),
      tier: isPro ? 'pro' : 'free',
      dataAccessWindow: isPro ? 'unlimited' : '24 hours',
      alertsLastHour: alertStats.alertsLastHour,
      alertsLastDay: alertStats.alertsLastDay,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('[Stats Error]', error);
    res.status(500).json({ error: error.message });
  }
});
router.get('/stats/overview', async (req, res) => {
  try {
    const isPro = isProTier(req);
    const indicators = await Indicator.findAll();
    const filtered = filterByTier(indicators, isPro);
    const overview = {
      totalIndicators: filtered.length,
      highRiskCount: filtered.filter(i => (i.risk_score || 0) >= 80).length,
      mediumRiskCount: filtered.filter(i => (i.risk_score || 0) >= 50 && (i.risk_score || 0) < 80).length,
      lowRiskCount: filtered.filter(i => (i.risk_score || 0) < 50).length,
      totalSources: new Set(filtered.map(i => (i.source || 'unknown').toLowerCase())).size,
      totalCountries: new Set(filtered.map(i => (i.country || 'Unknown').toUpperCase())).size,
      recentSevenDays: filtered.filter(i => new Date(i.last_seen || i.createdAt) >= new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)).length
    };
    res.json({
      tier: isPro ? 'pro' : 'free',
      dataAccessWindow: isPro ? 'unlimited' : '24 hours',
      overview,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('[Stats Overview Error]', error);
    res.status(500).json({ error: error.message });
  }
});
router.get('/stats/trends', async (req, res) => {
  res.status(410).json({ error: 'Trends feature has been removed.' });
});
router.get('/stats/geo', async (req, res) => {
  try {
    const isPro = isProTier(req);
    const indicators = await Indicator.findAll();
    const filtered = filterByTier(indicators, isPro);
    const countryDistribution = buildCountryDistribution(filtered, 12);
    const mapPoints = attachCountryCoordinates(countryDistribution);
    res.json({ countryDistribution, mapPoints, tier: isPro ? 'pro' : 'free', dataAccessWindow: isPro ? 'unlimited' : '24 hours', timestamp: new Date().toISOString() });
  } catch (error) {
    console.error('[Geo Stats Error]', error);
    res.status(500).json({ error: error.message });
  }
});
router.get('/indicators', async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '', type = '' } = req.query;
    const tier = req.headers['x-tier'] || 'free';
    const isPro = tier === 'pro';
    let timeFiltered = await Indicator.findAll();
    if (!isPro) {
      const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      timeFiltered = timeFiltered.filter(i => {
        const date = new Date(i.last_seen || i.createdAt);
        return date >= twentyFourHoursAgo;
      });
    }
    let filtered = timeFiltered;
    if (search) {
      filtered = searchIndicators(filtered, search, isPro).map(item => ({
        ...item,
        score: item._score
      }));
    }
    if (type) {
      filtered = filtered.filter(i => i.type === type);
    }
    const total = filtered.length;
    const offset = (page - 1) * limit;
    const rows = filtered.slice(offset, offset + parseInt(limit));
    res.json({
      total,
      page: parseInt(page),
      limit: parseInt(limit),
      pages: Math.ceil(total / limit),
      tier,
      dataAccessWindow: isPro ? 'unlimited' : '24 hours',
      data: rows
    });
  } catch (error) {
    console.error('[Indicators List Error]', error);
    res.status(500).json({ error: error.message });
  }
});
router.get('/indicators/stats/detailed', async (req, res) => {
  try {
    const isPro = isProTier(req);
    const indicators = await Indicator.findAll();
    const filtered = filterByTier(indicators, isPro);
    const stats = await Indicator.getStats();
    const filteredStats = {
      total: filtered.length,
      highRisk: filtered.filter(i => (i.risk_score || 0) >= 80).length,
      mediumRisk: filtered.filter(i => (i.risk_score || 0) >= 50 && (i.risk_score || 0) < 80).length,
      lowRisk: filtered.filter(i => (i.risk_score || 0) < 50).length,
      byType: filtered.reduce((acc, item) => { acc[item.type] = (acc[item.type] || 0) + 1; return acc; }, {}),
      bySource: filtered.reduce((acc, item) => { acc[item.source] = (acc[item.source] || 0) + 1; return acc; }, {}),
      byCountry: filtered.reduce((acc, item) => { acc[item.country] = (acc[item.country] || 0) + 1; return acc; }, {}),
      byThreatType: filtered.reduce((acc, item) => { acc[item.threat_type] = (acc[item.threat_type] || 0) + 1; return acc; }, {}),
      recentDays7: filtered.filter(i => new Date(i.last_seen || i.createdAt) >= new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)).length
    };
    res.json({
      tier: isPro ? 'pro' : 'free',
      dataAccessWindow: isPro ? 'unlimited' : '24 hours',
      overview: {
        total: filteredStats.total,
        highRisk: filteredStats.highRisk,
        mediumRisk: filteredStats.mediumRisk,
        lowRisk: filteredStats.lowRisk,
        recentDays7: filteredStats.recentDays7
      },
      breakdown: {
        byType: filteredStats.byType,
        bySource: filteredStats.bySource,
        byCountry: filteredStats.byCountry,
        byThreatType: filteredStats.byThreatType
      }
    });
  } catch (error) {
    console.error('[Stats Detailed Error]', error);
    res.status(500).json({ error: error.message });
  }
});
router.get('/indicators/:id', async (req, res) => {
  try {
    const tier = req.headers['x-tier'] || 'free';
    const isPro = tier === 'pro';
    const indicator = await Indicator.findById(req.params.id);
    if (!indicator) {
      return res.status(404).json({ error: 'Indicator not found' });
    }
    if (!isPro) {
      const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const lastSeen = new Date(indicator.last_seen || indicator.createdAt);
      if (lastSeen < cutoff) {
        return res.status(403).json({
          error: 'Indicator details are only available for the last 24 hours on the Free tier.',
          tier: 'free',
          requiredTier: 'pro'
        });
      }
    }
    res.json(indicator);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
router.get('/alerts', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] || 'user_demo_001';
    const tier = req.headers['x-tier'] || 'free';
    const isPro = tier === 'pro';
    const alerts = await getUserAlerts(userId);
    const filteredAlerts = isPro ? alerts : alerts.filter(a =>
      new Date(a.createdAt) >= new Date(Date.now() - 24 * 60 * 60 * 1000)
    );
    const now = new Date();
    const lastHour = new Date(now.getTime() - 60 * 60 * 1000);
    const lastDay = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const userAlertStats = {
      totalAlerts: filteredAlerts.length,
      pendingAlerts: filteredAlerts.filter(a => a.status === 'pending').length,
      alertsLastHour: filteredAlerts.filter(a => new Date(a.createdAt) >= lastHour).length,
      alertsLastDay: filteredAlerts.filter(a => new Date(a.createdAt) >= lastDay).length,
      byType: filteredAlerts.reduce((acc, a) => {
        acc[a.type] = (acc[a.type] || 0) + 1;
        return acc;
      }, {})
    };
    res.json({
      tier,
      dataAccessWindow: isPro ? 'unlimited' : '24 hours',
      userAlerts: filteredAlerts,
      stats: userAlertStats,
      message: isPro
        ? 'Showing full alert history for Pro tier.'
        : 'Free tier alerts are limited to the last 24 hours.'
    });
  } catch (error) {
    console.error('[Alerts Error]', error);
    res.status(500).json({ error: error.message });
  }
});
router.put('/alerts/:alertId/acknowledge', async (req, res) => {
  try {
    const alert = await acknowledgeAlert(req.params.alertId);
    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }
    res.json({ success: true, alert });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
router.get('/export/:type', async (req, res) => {
  try {
    const { type } = req.params;
    const tier = req.headers['x-tier'] || 'free';
    const isPro = tier === 'pro';
    if (!['pdf', 'csv', 'json'].includes(type)) return res.status(400).json({ error: 'Invalid export type' });
    if (!isPro && type !== 'json') {
      return res.status(403).json({ error: `${type.toUpperCase()} export is a Pro-tier feature.` });
    }
    const { start, end } = req.query;
    if (type === 'pdf') {
      const pdfBuffer = await generateThreatReport({ startDate: start, endDate: end, title: 'Threat Intelligence Report' });
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="ThreatView_Report_${new Date().toISOString().split('T')[0]}.pdf"`);
      return res.send(Buffer.from(pdfBuffer));
    }
    if (type === 'csv') {
      const csv = await generateCSVExport({ startDate: start, endDate: end });
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="ThreatView_Indicators_${new Date().toISOString().split('T')[0]}.csv"`);
      return res.send(csv);
    }
    if (type === 'json') {
      const json = await generateJSONExport({ startDate: start, endDate: end });
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="ThreatView_Indicators_${new Date().toISOString().split('T')[0]}.json"`);
      return res.send(json);
    }
  } catch (error) {
    console.error('[Export Error]', error);
    res.status(500).json({ error: 'Failed to generate export' });
  }
});
router.post('/ingestion/manual-sync', async (req, res) => {
  try {
    console.log('🔄 Manual sync triggered via API');
    const result = await runFullSyncCycle();
    res.json({
      success: true,
      message: 'Ingestion cycle completed',
      summary: {
        totalCreated: result.totalCreated,
        sources: result.results
      }
    });
  } catch (error) {
    console.error('[Manual Sync Error]', error);
    res.status(500).json({ error: error.message });
  }
});
router.get('/ingestion/status', async (req, res) => {
  try {
    const dbData = db.read();
    const totalIndicators = dbData.indicators.length;
    const lastSync = dbData.metadata.lastSync;
    res.json({
      status: 'active',
      totalIndicators,
      lastSync,
      schedulerEnabled: process.env.ENABLE_SCHEDULED_INGESTION !== 'false',
      ingestionInterval: `${process.env.INGESTION_INTERVAL_MINUTES || 60} minutes`,
      dataStoreType: 'Local JSON',
      nextSync: new Date(new Date(lastSync).getTime() + 60 * 60 * 1000).toISOString()
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
router.post('/subscriptions', async (req, res) => {
  try {
    const { email, tier } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    const subscription = await db.addSubscription(email, tier || 'free');
    res.json({
      success: true,
      subscription,
      message: `Subscribed to ThreatView (${subscription.tier} tier)`
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
router.get('/subscriptions', async (req, res) => {
  try {
    const subscriptions = await db.getSubscriptions();
    res.json({
      total: subscriptions.length,
      subscriptions,
      tierBreakdown: {
        free: subscriptions.filter(s => s.tier === 'free').length,
        pro: subscriptions.filter(s => s.tier === 'pro').length
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
router.get('/brand/search', async (req, res) => {
  try {
    const { domain = '' } = req.query;
    const tier = req.headers['x-tier'] || 'free';
    const isPro = tier === 'pro';
    if (!domain || !domain.toString().trim()) {
      return res.status(400).json({ error: 'Query parameter domain is required' });
    }
    const domains = domain
      .toString()
      .split(',')
      .map(normalizeDomain)
      .filter(Boolean);
    const all = await Indicator.findAll();
    const filtered = filterByTier(all, isPro);
    const matches = filtered
      .map((item) => {
        const matchedDomains = domains.filter((domainValue) =>
          matchBrandIndicator(item.indicator, domainValue)
        );
        if (matchedDomains.length === 0) return null;
        return {
          ...item,
          matchedDomains,
          matchType: resolveMatchType(item.indicator, matchedDomains[0])
        };
      })
      .filter(Boolean)
      .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
    const matchCount = matches.length;
    const highestRisk = matches.reduce((max, item) => Math.max(max, item.risk_score || 0), 0);
    const domainsSearched = [...new Set(domains)];
    res.json({
      domain,
      domainsSearched,
      tier,
      dataAccessWindow: isPro ? 'unlimited' : '24 hours',
      matchCount,
      highestRisk,
      status: matchCount > 0 ? 'ALERT' : 'CLEAR',
      note: isPro
        ? 'Full history search enabled for Pro tier.'
        : 'Free tier search is limited to the last 24 hours of indicators.',
      message: matchCount > 0
        ? `⚠ Found ${matchCount} indicators matching ${domainsSearched.join(', ')}`
        : `✓ No mentions of ${domainsSearched.join(', ')} found in current threat feeds`,
      matches: matches.map((m) => ({
        id: m.id,
        indicator: m.indicator,
        type: m.type,
        threat_type: m.threat_type,
        risk_score: m.risk_score,
        source: m.source,
        country: m.country,
        matchedDomains: m.matchedDomains,
        matchType: m.matchType,
        last_seen: m.last_seen || m.createdAt
      }))
    });
  } catch (error) {
    console.error('[Brand Error]', error);
    res.status(500).json({ error: error.message });
  }
});
router.get('/search', async (req, res) => {
  try {
    const { query = '' } = req.query;
    const tier = req.headers['x-tier'] || 'free';
    const isPro = tier === 'pro';
    if (!query || !query.trim()) return res.status(400).json({ error: 'Query parameter is required' });
    const all = await Indicator.findAll();
    const filtered = filterByTier(all, isPro);
    const results = searchIndicators(filtered, query, isPro);
    res.json({
      query,
      tier,
      dataAccessWindow: isPro ? 'unlimited' : '24 hours',
      totalMatches: results.length,
      results: results.map(m => ({
        id: m.id,
        indicator: m.indicator,
        type: m.type,
        threat_type: m.threat_type,
        risk_score: m.risk_score,
        source: m.source,
        country: m.country,
        industry_targets: m.industry_targets,
        last_seen: m.last_seen || m.createdAt,
        score: m._score
      }))
    });
  } catch (error) {
    console.error('[Search Error]', error);
    res.status(500).json({ error: error.message });
  }
});
router.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'ThreatView API',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});
let alertRules = [
  { id: 1, name: 'High Severity Alert', condition: 'Severity == "high"', action: 'Send_Email("admin@threatview.com")', enabled: true },
  { id: 2, name: 'Brand Phishing Alert', condition: 'Type == "phishing" AND IOC.includes("threatview")', action: 'Send_Email("security@threatview.com")', enabled: true },
];
router.get('/alerts/rules', (req, res) => {
  res.json({ rules: alertRules });
});
router.post('/alerts/rules', (req, res) => {
  const { name, condition, action } = req.body;
  const newRule = {
    id: Date.now(),
    name,
    condition,
    action,
    enabled: true
  };
  alertRules.push(newRule);
  res.json({ success: true, rule: newRule });
});
router.patch('/alerts/rules/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const rule = alertRules.find(r => r.id === id);
  if (!rule) return res.status(404).json({ error: 'Rule not found' });
  if (req.body.enabled !== undefined) rule.enabled = req.body.enabled;
  if (req.body.name) rule.name = req.body.name;
  if (req.body.condition) rule.condition = req.body.condition;
  if (req.body.action) rule.action = req.body.action;
  res.json({ success: true, rule });
});
router.delete('/alerts/rules/:id', (req, res) => {
  const id = parseInt(req.params.id);
  alertRules = alertRules.filter(r => r.id !== id);
  res.json({ success: true });
});
module.exports = router;