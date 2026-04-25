const Indicator = require('../models/Indicator');
const EmailService = require('./emailService');
const defaultUserProfile = {
  id: 'user_demo_001',
  name: 'Security Admin',
  email: 'admin@threatview.com',
  industry: 'Healthcare',
  trackedDomains: ['healthcare.com', 'medicalcorp.com'],
  alertThreshold: 80,
  enableAlerts: true,
  tier: 'pro'
};
class AlertEngine {
  checkIndustryMatch(indicator, user) {
    if (!indicator.industry_targets || !user.industry) {
      return null;
    }
    const targets = indicator.industry_targets.toLowerCase();
    const userIndustry = user.industry.toLowerCase();
    if (targets.includes(userIndustry) || targets.includes('all') || targets.includes('general')) {
      return {
        type: 'INDUSTRY_MATCH',
        severity: 'HIGH',
        reason: `New threat targeting ${user.industry} industry detected`,
        priority: Math.min(100, indicator.risk_score + 10)
      };
    }
    return null;
  }
  checkBrandMonitoring(indicator, user) {
    if (!user.trackedDomains || user.trackedDomains.length === 0) {
      return null;
    }
    const indicatorLower = (indicator.indicator || '').toLowerCase();
    for (const domain of user.trackedDomains) {
      if (indicatorLower.includes(domain.toLowerCase())) {
        return {
          type: 'BRAND_ALERT',
          severity: 'CRITICAL',
          reason: `Your domain "${domain}" detected in threat indicator`,
          priority: 100,
          domain
        };
      }
    }
    return null;
  }
  checkRiskThreshold(indicator, user) {
    const threshold = user.alertThreshold || 80;
    if (indicator.risk_score >= threshold) {
      return {
        type: 'RISK_THRESHOLD',
        severity: indicator.risk_score >= 90 ? 'CRITICAL' : 'HIGH',
        reason: `High risk indicator (${indicator.risk_score}/100)`,
        priority: indicator.risk_score
      };
    }
    return null;
  }
  checkVulnerabilityAlert(indicator, user) {
    const threatLower = (indicator.threat_type || '').toLowerCase();
    const isZeroDay = /zero\-day|0\-day|unpatched/i.test(threatLower);
    const hasCVE = /cve\-[0-9]{4}\-[0-9]{4,}/i.test(indicator.indicator + ' ' + threatLower);
    if (isZeroDay || hasCVE) {
      return {
        type: 'VULNERABILITY_ALERT',
        severity: 'CRITICAL',
        reason: isZeroDay ? 'Zero-day vulnerability detected' : 'CVE vulnerability detected',
        priority: 100
      };
    }
    return null;
  }
  checkRansomwareAlert(indicator, user) {
    const threatLower = (indicator.threat_type || '').toLowerCase();
    if (threatLower.includes('ransomware') || threatLower.includes('lockbit') || threatLower.includes('blackcat')) {
      return {
        type: 'RANSOMWARE_ALERT',
        severity: 'CRITICAL',
        reason: `Ransomware variant detected: ${indicator.threat_type}`,
        priority: 100
      };
    }
    return null;
  }
  checkGeoAlert(indicator, user) {
    const highRiskCountries = ['KP', 'IR', 'SY', 'CU'];
    if (highRiskCountries.includes(indicator.country)) {
      return {
        type: 'GEO_ALERT',
        severity: 'HIGH',
        reason: `Threat originating from high-risk country: ${indicator.country}`,
        priority: 85
      };
    }
    return null;
  }
  evaluateAllRules(indicator, user) {
    const alerts = [];
    const checks = [
      this.checkIndustryMatch(indicator, user),
      this.checkBrandMonitoring(indicator, user),
      this.checkRiskThreshold(indicator, user),
      this.checkVulnerabilityAlert(indicator, user),
      this.checkRansomwareAlert(indicator, user),
      this.checkGeoAlert(indicator, user)
    ];
    checks.forEach(alert => {
      if (alert) alerts.push(alert);
    });
    return alerts;
  }
}
const engine = new AlertEngine();
let emailCircuitBreaker = {
  active: false,
  reason: null,
  timestamp: null
};

const resetCircuitBreaker = () => {
  emailCircuitBreaker = { active: false, reason: null, timestamp: null };
};
const checkAlerts = async (newIndicator, users = null) => {
  const userList = users || [defaultUserProfile];
  console.log(`\n🔔 [ALERT ENGINE] Processing indicator: ${newIndicator.indicator}`);
  for (const user of userList) {
    if (!user.enableAlerts) {
      console.log(`  ⏭️  Alerts disabled for ${user.email}`);
      continue;
    }
    const matchingAlerts = engine.evaluateAllRules(newIndicator, user);
    if (matchingAlerts.length === 0) {
      console.log(`  ℹ️  No alerts triggered for ${user.email}`);
      continue;
    }
    for (const alert of matchingAlerts) {
      console.log(`  🚨 [${alert.type}] ${alert.severity} - ${alert.reason}`);
      let deliveryMetadata = { method: 'email', status: 'skipped' };
      
      if (process.env.ENABLE_EMAIL_ALERTS !== 'false') {
        if (emailCircuitBreaker.active) {
          console.log(`  🚫 Email delivery paused: ${emailCircuitBreaker.reason}`);
          deliveryMetadata.status = 'paused_by_limit';
        } else {
          const emailResult = await EmailService.sendAlertNotification(
            user,
            newIndicator,
            alert.reason
          );
          
          deliveryMetadata = {
            method: 'email',
            status: emailResult.success ? (emailResult.mockMode ? 'mocked' : 'sent') : 'failed',
            error: emailResult.error || null,
            timestamp: new Date().toISOString()
          };

          if (emailResult.success || emailResult.mockMode) {
            console.log(`  ✉️  Notification ${emailResult.mockMode ? 'MOCKED' : 'SENT'} to ${user.email}`);
          } else {
            console.error(`  ❌ Failed to send email: ${emailResult.error}`);
            if (emailResult.error && (emailResult.error.includes('messaging limits') || emailResult.error.includes('Forbidden'))) {
              emailCircuitBreaker = {
                active: true,
                reason: 'Messaging limits exceeded',
                timestamp: new Date()
              };
              console.warn('  ⚠️ CIRCUIT BREAKER ACTIVATED: Pausing further emails for this cycle.');
            }
          }
        }
      }
      await Indicator.logAlert(newIndicator, user, alert.reason, deliveryMetadata);
    }
  }
  console.log('');
};
const getAlertStats = async () => {
  const data = require('../database').read();
  const alerts = data.alerts || [];
  const now = new Date();
  const lastHour = new Date(now.getTime() - 60 * 60 * 1000);
  const lastDay = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  return {
    totalAlerts: alerts.length,
    alertsLastHour: alerts.filter(a => new Date(a.createdAt) >= lastHour).length,
    alertsLastDay: alerts.filter(a => new Date(a.createdAt) >= lastDay).length,
    alertsByType: _groupBy(alerts, 'type'),
    pendingAlerts: alerts.filter(a => a.status === 'pending').length
  };
};
const getUserAlerts = async (userId) => {
  const data = require('../database').read();
  const alerts = data.alerts || [];
  return alerts.filter(a => a.userId === userId);
};
const acknowledgeAlert = async (alertId) => {
  const data = require('../database').read();
  const alert = data.alerts.find(a => a.id === alertId);
  if (alert) {
    alert.status = 'acknowledged';
    alert.acknowledgedAt = new Date().toISOString();
    require('../database')._writeSync(data);
  }
  return alert;
};
const _groupBy = (array, key) => {
  return array.reduce((acc, obj) => {
    acc[obj[key]] = (acc[obj[key]] || 0) + 1;
    return acc;
  }, {});
};
module.exports = {
  checkAlerts,
  getAlertStats,
  getUserAlerts,
  acknowledgeAlert,
  resetCircuitBreaker,
  AlertEngine,
  engine
};