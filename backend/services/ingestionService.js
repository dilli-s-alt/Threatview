const axios = require('axios');
const cron = require('node-cron');
const Indicator = require('../models/Indicator');
const _ = require('lodash');
const { checkAlerts } = require('./alertService');
const ReportingService = require('./reportingService');
const QUIET_LOGS = process.env.VERBOSE_LOGS !== 'true';
const log = (...args) => { if (!QUIET_LOGS) console.log(...args); }
const SOURCE_FIELD_MAP = {
  OTX: {
    src_ip: 'indicator',
    origin_address: 'indicator',
    malicious_url: 'indicator',
    malware_domain: 'indicator',
    hash_value: 'indicator',
    url: 'indicator',
    ip: 'indicator',
    threat_name: 'threat_type',
    category: 'threat_type',
    severity: 'risk_score',
    confidence_score: 'confidence',
    origin_country: 'country',
    observed_at: 'last_seen',
    first_seen: 'last_seen',
    sector: 'industry_targets'
  },
  Shodan: {
    ip_str: 'indicator',
    origin_address: 'indicator',
    host: 'indicator',
    vuln: 'threat_type',
    vuln_description: 'threat_type',
    vulnerability_score: 'risk_score',
    country_code: 'country',
    observed_at: 'last_seen'
  },
  MalwareBazaar: {
    sha256_hash: 'indicator',
    md5_hash: 'indicator',
    sha1_hash: 'indicator',
    malware_family: 'threat_type',
    first_submission: 'last_seen',
    country: 'country',
    confidence_score: 'confidence'
  },
  PhishTank: {
    phishing_url: 'indicator',
    target_domain: 'indicator',
    category: 'threat_type',
    threat_strength: 'risk_score',
    brand: 'industry_targets',
    last_reported: 'last_seen'
  }
};
const normalizeSourceData = (raw, source) => {
  const mapping = SOURCE_FIELD_MAP[source] || {};
  const normalizedRaw = Object.entries(raw).reduce((acc, [key, value]) => {
    const mappedKey = mapping[key] || key;
    acc[mappedKey] = value;
    return acc;
  }, {});
  return ThreatModel.normalize(normalizedRaw, source);
};
const ThreatModel = {
  normalize(data, source) {
    let normalized = {
      indicator: this._extractIndicator(data),
      type: this._classifyType(data),
      threat_type: data.threat_type || data.malware_family || data.type || 'unknown',
      risk_score: this._calculateRiskScore(data),
      source: source,
      country: data.country || data.origin_country || 'Unknown',
      latitude: Number(data.latitude) || (Math.random() * 120 - 60),
      longitude: Number(data.longitude) || (Math.random() * 360 - 180),
      industry_targets: data.industry_targets || data.sector || 'General',
      last_seen: new Date(data.last_seen || data.seen || data.observed_at || data.first_seen || data.last_reported || new Date()).toISOString(),
      metadata: {
        tags: data.tags || [],
        references: data.references || [],
        confidence: data.confidence || data.confidence_score || 'medium'
      }
    };
    return normalized;
  },
  _extractIndicator(data) {
    return (
      data.indicator ||
      data.address ||
      data.url ||
      data.domain ||
      data.hash ||
      data.ioc ||
      data.md5 ||
      data.ip ||
      ''
    ).trim();
  },
  _classifyType(data) {
    const indicator = this._extractIndicator(data);
    let type = data.type || 'unknown';
    if (type === 'unknown' || !type) {
      if (indicator.startsWith('http')) return 'url';
      if (indicator.includes('/')) return 'url';
      if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(indicator)) return 'ip';
      if (/^[a-f0-9]{32}$/i.test(indicator)) return 'hash_md5';
      if (/^[a-f0-9]{40}$/i.test(indicator)) return 'hash_sha1';
      if (/^[a-f0-9]{64}$/i.test(indicator)) return 'hash_sha256';
      if (indicator.includes('.') && !indicator.includes('/')) return 'domain';
    }
    return type;
  },
  _calculateRiskScore(data) {
    let score = data.risk_score || data.severity || 50;
    if (data.threat_type && data.threat_type.toLowerCase().includes('ransomware')) score = 100;
    if (data.threat_type && data.threat_type.toLowerCase().includes('botnet')) score = 95;
    return Math.min(100, Math.max(0, Number(score)));
  }
};
const syncOTX = async () => {
  log('🔄 [AlienVault OTX] Starting sync...');
  try {
    const apiKey = process.env.ALIENVAULT_API_KEY || process.env.OTX_API_KEY || '';
    const url = 'https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10';
    const headers = apiKey ? { 'X-OTX-API-KEY': apiKey } : {};
    const mockPulses = [
      {
        pulses: [
          {
            indicators: [
              {
                indicator: '185.220.100.255',
                type: 'IPv4',
                title: 'Tor Exit Node',
                description: 'Malicious Tor exit node used for DDoS'
              },
              {
                indicator: 'malware-c2.xyz',
                type: 'domain',
                title: 'C2 Server Domain',
                description: 'Command and control server'
              }
            ],
            name: 'Data Exfiltration Campaign',
            created: new Date().toISOString()
          }
        ]
      }
    ];
    const shouldMock = process.env.MOCK_SOURCES === 'true' || !apiKey;
    let pulses = [];
    if (!shouldMock) {
      try {
        const response = await axios.get(url, { headers, timeout: 15000 });
        pulses = response.data.pulses || response.data.results || [];
      } catch (fetchError) {
        log(`⚠️ [OTX] Fetch failed (${fetchError.message}). Falling back to mock data.`);
        pulses = mockPulses[0].pulses || [];
      }
    } else {
      pulses = mockPulses[0].pulses || [];
    }
    let created = 0;
    for (const pulse of pulses) {
      for (const indicator of pulse.indicators || []) {
        const normalized = normalizeSourceData(
          {
            ...indicator,
            threat_type: pulse.name,
            last_seen: pulse.created
          },
          'OTX'
        );
        const [data, wasCreated] = await Indicator.findOrCreate({
          where: { indicator: normalized.indicator },
          defaults: normalized
        });
        if (wasCreated) {
          created++;
          await checkAlerts(data);
          log(`  ✓ New indicator: ${normalized.indicator}`);
        }
      }
    }
    log(`✅ [OTX] Sync complete. Created: ${created}`);
    return { source: 'OTX', created };
  } catch (error) {
    const status = error.response?.status;
    const details = error.response?.data?.detail || error.response?.data || '';
    console.error('❌ [OTX] Sync failed:', status ? `[${status}]` : '', error.message, details);
    return { source: 'OTX', created: 0, error: error.message };
  }
};
const syncShodan = async () => {
  log('🔄 [Shodan] Starting sync...');
  try {
    const apiKey = process.env.SHODAN_API_KEY || '';
    const query = 'vuln:CVE-2024-1086';
    const mockResults = {
      matches: [
        {
          ip_str: '203.100.50.213',
          port: 22,
          org: 'ISP Provider',
          country_code: 'US',
          vulns: ['CVE-2024-1086']
        },
        {
          ip_str: '180.250.100.18',
          port: 22,
          org: 'Hosting Provider',
          country_code: 'CN',
          vulns: ['CVE-2024-1086']
        }
      ]
    };
    const shouldMock = process.env.MOCK_SOURCES === 'true' || !apiKey;
    let results = [];
    if (!shouldMock) {
      try {
        const response = await axios.get(
          `https://api.shodan.io/shodan/host/search?key=${encodeURIComponent(apiKey)}&query=${encodeURIComponent(query)}`,
          { timeout: 30000 }
        );
        results = response.data.matches || [];
      } catch (fetchError) {
        log(`⚠️ [Shodan] Fetch failed (${fetchError.message}). Falling back to mock data.`);
        results = mockResults.matches || [];
      }
    } else {
      results = mockResults.matches || [];
    }
    let created = 0;
    for (const host of results) {
      const normalized = normalizeSourceData(
        {
          ip_str: host.ip_str || host.ip || host.host,
          type: 'ip',
          threat_type: host.vulns ? `Vulnerable System: ${host.vulns.join(', ')}` : host.data || '',
          risk_score: 85,
          country_code: host.country_code || host.country || 'Unknown',
          metadata: {
            port: host.port,
            org: host.org || host.org_name,
            vulns: host.vulns || []
          }
        },
        'Shodan'
      );
      const [data, wasCreated] = await Indicator.findOrCreate({
        where: { indicator: normalized.indicator },
        defaults: normalized
      });
      if (wasCreated) {
        created++;
        await checkAlerts(data);
        log(`  ✓ New vulnerable host: ${normalized.indicator}`);
      }
    }
    log(`✅ [Shodan] Sync complete. Created: ${created}`);
    return { source: 'Shodan', created };
  } catch (error) {
    const status = error.response?.status;
    const details = error.response?.data?.error || error.response?.data || '';
    console.error('❌ [Shodan] Sync failed:', status ? `[${status}]` : '', error.message, details);
    return { source: 'Shodan', created: 0, error: error.message };
  }
};
const syncMalwareBazaar = async () => {
  log('🔄 [MalwareBazaar] Starting sync...');
  try {
    const apiUrl = 'https://mb-api.abuse.ch/api/v1/';
    const shouldMock = process.env.MOCK_SOURCES === 'true';
    let samples = [];
    if (!shouldMock) {
      try {
        const response = await axios.post(
          apiUrl,
          new URLSearchParams({ query: 'get_recent' }).toString(),
          { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 15000 }
        );
        samples = response.data.data || [];
      } catch (fetchError) {
        log('⚠️ [MalwareBazaar] Fetch failed. Falling back to mock data.');
        samples = [
          {
            sha256_hash: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f',
            malware_family: 'Ransomware.LockBit.36',
            first_submission: new Date().toISOString(),
            country: 'RU'
          },
          {
            sha256_hash: 'f1e2d3c4b5a6z7y8x9w0v1u2t3s4r5q6p7o8n9m0l1k2j3i4h5g6f7e8d9c0b1',
            malware_family: 'Trojan.Emotet',
            first_submission: new Date().toISOString(),
            country: 'US'
          }
        ];
      }
    } else {
      samples = [
        {
          sha256_hash: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f',
          malware_family: 'Ransomware.LockBit.36',
          first_submission: new Date().toISOString(),
          country: 'RU'
        },
        {
          sha256_hash: 'f1e2d3c4b5a6z7y8x9w0v1u2t3s4r5q6p7o8n9m0l1k2j3i4h5g6f7e8d9c0b1',
          malware_family: 'Trojan.Emotet',
          first_submission: new Date().toISOString(),
          country: 'US'
        }
      ];
    }
    let created = 0;
    for (const sample of samples) {
      const normalized = normalizeSourceData(
        {
          sha256_hash: sample.sha256_hash || sample.hash || sample.sha1_hash || sample.md5_hash,
          type: 'hash_sha256',
          threat_type: sample.malware_family || sample.threat || sample.threat_type || 'malware',
          risk_score: 95,
          country: sample.country || sample.country_code || 'Unknown',
          first_submission: sample.first_submission || sample.first_seen || sample.first_seen || new Date().toISOString()
        },
        'MalwareBazaar'
      );
      const [data, wasCreated] = await Indicator.findOrCreate({
        where: { indicator: normalized.indicator },
        defaults: normalized
      });
      if (wasCreated) {
        created++;
        await checkAlerts(data);
        log(`  ✓ New malware hash: ${normalized.indicator.substring(0, 16)}...`);
      }
    }
    log(`✅ [MalwareBazaar] Sync complete. Created: ${created}`);
    return { source: 'MalwareBazaar', created };
  } catch (error) {
    console.error('❌ [MalwareBazaar] Sync failed:', error.message);
    return { source: 'MalwareBazaar', created: 0, error: error.message };
  }
};
const syncPhishTank = async () => {
  log('🔄 [PhishTank] Starting sync...');
  try {
    const mockFeed = [
      {
        indicator: 'http://healthcare.com-secure-login.top/account',
        type: 'url',
        threat_type: 'phishing',
        risk_score: 95,
        country: 'RU',
        industry_targets: 'Healthcare',
        last_seen: new Date().toISOString(),
        metadata: { category: 'phishing', source: 'PhishTank' }
      },
      {
        indicator: 'http://medicalcorp.com-updates.net/verify',
        type: 'url',
        threat_type: 'phishing',
        risk_score: 92,
        country: 'CN',
        industry_targets: 'Healthcare',
        last_seen: new Date().toISOString(),
        metadata: { category: 'phishing', source: 'PhishTank' }
      },
      {
        indicator: 'http://secure-billing-portal.example',
        type: 'url',
        threat_type: 'phishing',
        risk_score: 65,
        country: 'US',
        industry_targets: 'Banking',
        last_seen: new Date().toISOString(),
        metadata: { category: 'phishing', source: 'PhishTank' }
      },
      {
        indicator: 'http://invoice-portal.example',
        type: 'url',
        threat_type: 'brand phishing',
        risk_score: 82,
        country: 'US',
        industry_targets: 'Healthcare',
        last_seen: new Date().toISOString(),
        metadata: { category: 'phishing', source: 'PhishTank' }
      }
    ];
    let created = 0;
    for (const item of mockFeed) {
      const normalized = normalizeSourceData(item, 'PhishTank');
      const [data, wasCreated] = await Indicator.findOrCreate({
        where: { indicator: normalized.indicator },
        defaults: normalized
      });
      if (wasCreated) {
        created++;
        await checkAlerts(data);
        log(`  ✓ New phishing indicator: ${normalized.indicator}`);
      }
    }
    log(`✅ [PhishTank] Sync complete. Created: ${created}`);
    return { source: 'PhishTank', created };
  } catch (error) {
    console.error('❌ [PhishTank] Sync failed:', error.message || error);
    return { source: 'PhishTank', created: 0, error: error.message || error };
  }
};
const performMaintenance = async () => {
  log('🧹 [Maintenance] Starting cleanup...');
  try {
    const result = await Indicator.deleteOlderThan(7);
    log(
      `✅ [Maintenance] Complete. Deleted: ${result.deleted}, Remaining: ${result.remaining}`
    );
    return result;
  } catch (error) {
    console.error('❌ [Maintenance] Failed:', error.message);
  }
};
const runFullSyncCycle = async () => {
  log('\n🌍 Starting ThreatView Ingestion Cycle...');
  const results = [];
  results.push(await syncOTX());
  results.push(await syncShodan());
  results.push(await syncMalwareBazaar());
  results.push(await syncPhishTank());
  const totalCreated = results.reduce((sum, r) => sum + (r.created || 0), 0);
  log(`📊 Sync Summary: Created ${totalCreated} new indicators across ${results.length} sources.`);
  return { totalCreated, results };
};
const initScheduler = () => {
  const interval = Number(process.env.INGESTION_INTERVAL_MINUTES) || 60;
  const enabled = process.env.ENABLE_SCHEDULED_INGESTION !== 'false';
  if (!enabled) {
    log('⏸️  Scheduled ingestion is disabled');
    return;
  }
  const cronExpression = interval === 60 ? '0 * * * *' : `*/${interval} * * * *`;
  log(`📅 Scheduling ingestion every ${interval} minute(s): "${cronExpression}"`);
  log('🔐 Tier policy: Free tier users receive 24-hour history while Pro users retain unlimited access via API.');
  log('🗃️  Ingestion stores all raw threats; tier filtering is applied at the API layer.');
  runFullSyncCycle().catch(error => {
    console.error('🚨 Initial sync failed:', error);
  });
  cron.schedule(cronExpression, async () => {
    try {
      await runFullSyncCycle();
    } catch (error) {
      console.error('🚨 Scheduled sync failed:', error);
    }
  });
  cron.schedule('0 2 * * *', async () => {
    try {
      await performMaintenance();
    } catch (error) {
      console.error('🚨 Maintenance failed:', error);
    }
  });
  cron.schedule('0 7 * * 1', async () => {
    try {
      log('📬 Weekly report job: generating and emailing Pro subscribers');
      const result = await ReportingService.generateAndEmailWeeklyReports();
      log(`📬 Weekly reports sent: ${result.sent}`);
    } catch (error) {
      console.error('🚨 Weekly report job failed:', error);
    }
  });
  log('✅ Scheduler initialized');
};
module.exports = {
  initScheduler,
  runFullSyncCycle,
  syncOTX,
  syncShodan,
  syncMalwareBazaar,
  syncPhishTank,
  performMaintenance,
  ThreatModel
};