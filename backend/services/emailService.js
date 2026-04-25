const sgMail = require('@sendgrid/mail');
const fs = require('fs');
const path = require('path');
class EmailService {
  constructor() {
    this.enabled = process.env.ENABLE_EMAIL_ALERTS !== 'false';
    this.sendgridKey = process.env.SENDGRID_API_KEY || '';
    this.fromEmail = process.env.SENDGRID_FROM_EMAIL || 'noreply@threatview.com';
    this.mockMode = 
      process.env.MOCK_EMAIL === 'true' || 
      !this.sendgridKey || 
      this.sendgridKey.length < 10 ||
      this.sendgridKey.includes('test');
    
    // Use process.cwd() for more reliable pathing in production
    this.mockFilePath = path.resolve(process.cwd(), 'mock_emails.json');
    if (!this.mockMode) {
      sgMail.setApiKey(this.sendgridKey);
      if (process.env.VERBOSE_LOGS === 'true') {
        console.log(`🚀 Email service INITIALIZED in LIVE mode (Sender: ${this.fromEmail})`);
      }
    } else {
      if (process.env.VERBOSE_LOGS === 'true') {
        console.log('⚠️  Email service running in MOCK MODE (Alerts will be saved to mock_emails.json)');
      }
      this._initMockFile();
    }
  }
  _initMockFile() {
    if (!fs.existsSync(this.mockFilePath)) {
      fs.writeFileSync(this.mockFilePath, JSON.stringify([], null, 2));
    }
  }
  _saveMockEmail(data) {
    try {
      const current = JSON.parse(fs.readFileSync(this.mockFilePath, 'utf8'));
      current.unshift({ ...data, id: Date.now().toString(36) });
      fs.writeFileSync(this.mockFilePath, JSON.stringify(current.slice(0, 50), null, 2));
    } catch (e) {
      console.error('Failed to save mock email:', e.message);
    }
  }
  async sendAlertNotification(user, indicator, reason) {
    if (!this.enabled) return { success: false, reason: 'Email alerts disabled' };
    const subject = `🚨 THREATVIEW ALERT: ${indicator.threat_type}`;
    const htmlContent = this._buildAlertEmail(user, indicator, reason);
    const textContent = this._buildAlertEmailText(user, indicator, reason);
    return this._sendEmail({
      to: user.email,
      subject,
      html: htmlContent,
      text: textContent,
      priority: 'high'
    });
  }
  async sendDailySummary(user, summary) {
    if (!this.enabled) return { success: false, reason: 'Email alerts disabled' };
    const subject = `📊 ThreatView Daily Summary - ${new Date().toLocaleDateString()}`;
    const htmlContent = this._buildSummaryEmail(user, summary);
    return this._sendEmail({
      to: user.email,
      subject,
      html: htmlContent
    });
  }
  async sendReport(user, pdfBuffer, reportName) {
    if (!this.enabled) return { success: false, reason: 'Email alerts disabled' };
    const subject = `📋 ThreatView Report: ${reportName}`;
    const htmlContent = this._buildReportEmail(user, reportName);
    return this._sendEmail({
      to: user.email,
      subject,
      html: htmlContent,
      attachments: [
        {
          filename: `${reportName}.pdf`,
          content: pdfBuffer,
          contentType: 'application/pdf'
        }
      ]
    });
  }
  async _sendEmail(options) {
    const emailData = {
      from: this.fromEmail,
      to: options.to,
      subject: options.subject,
      html: options.html,
      text: options.text || '',
      priority: options.priority || 'normal',
      timestamp: new Date().toISOString()
    };
    if (this.mockMode) {
      this._saveMockEmail(emailData);
      console.log('\n' + '═'.repeat(60));
      console.log('📧 [EMAIL MOCK] - Details saved to mock_emails.json');
      console.log('═'.repeat(60));
      console.log(`To: ${emailData.to}`);
      console.log(`Subject: ${emailData.subject}`);
      console.log('─'.repeat(60));
      console.log(emailData.text || 'HTML content generated (see mock_emails.json)');
      console.log('═'.repeat(60) + '\n');
      return { success: true, mockMode: true, ...emailData };
    }
    try {
      const msg = {
        from: emailData.from,
        to: emailData.to,
        subject: emailData.subject,
        text: emailData.text,
        html: emailData.html,
        headers: {
          'Priority': emailData.priority
        }
      };
      if (options.attachments && Array.isArray(options.attachments)) {
        msg.attachments = options.attachments.map(att => ({
          content: Buffer.isBuffer(att.content) ? att.content.toString('base64') : Buffer.from(att.content || '', 'utf8').toString('base64'),
          filename: att.filename,
          type: att.contentType || 'application/octet-stream',
          disposition: 'attachment'
        }));
      }
      await sgMail.send(msg);
      console.log(`✅ [LIVE] Email successfully sent to ${emailData.to}`);
      return { success: true, ...emailData };
    } catch (error) {
      const isForbidden = error.response?.body?.errors?.some(e => e.message.includes('verified Sender Identity'));
      
      if (isForbidden) {
        console.warn('⚠️  Live email failed (Unverified Sender). Falling back to MOCK mode for this request.');
        this.mockMode = true; // Permanent fallback for this instance
        this._initMockFile();
        this._saveMockEmail(emailData);
        return { success: true, mockMode: true, ...emailData };
      }

      console.error('\n' + '✖'.repeat(60));
      console.error('❌ EMAIL DELIVERY FAILED');
      console.error('✖'.repeat(60));
      console.error('Error:', error.message);
      
      if (error.response?.body) {
        console.error('Details:', JSON.stringify(error.response.body, null, 2));
      }

      if (isForbidden) {
        console.error('\n💡 TIP: Ensure your SENDGRID_FROM_EMAIL is a VERIFIED SENDER in your SendGrid dashboard.');
        console.error('👉 Visit: https://app.sendgrid.com/settings/sender_auth\n');
      }
      console.error('═'.repeat(60) + '\n');
      
      return { success: false, error: error.message, isMock: false };
    }
  }
  _buildAlertEmail(user, indicator, reason) {
    const color = this._riskColor(indicator.risk_score);
    return `
    <html>
      <body style="margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;background-color:#f8fafc;color:#1e293b;">
        <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color:#f8fafc;padding:40px 20px;">
          <tr>
            <td align="center">
              <table width="600" border="0" cellspacing="0" cellpadding="0" style="background-color:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 10px 25px rgba(0,0,0,0.05);border:1px solid #e2e8f0;">
                <tr>
                  <td style="background-color:#6366f1;padding:32px;text-align:center;">
                    <h1 style="margin:0;color:#ffffff;font-size:24px;font-weight:800;letter-spacing:0.05em;text-transform:uppercase;">ThreatView</h1>
                    <div style="color:rgba(255,255,255,0.8);font-size:14px;margin-top:4px;">Security Intelligence Alert</div>
                  </td>
                </tr>
                <tr>
                  <td style="padding:40px;">
                    <h2 style="margin:0 0 16px 0;font-size:20px;color:#0f172a;">New Threat Detected</h2>
                    <p style="margin:0 0 24px 0;line-height:1.6;color:#64748b;">Hi ${user.name || user.email}, we've detected a high-priority threat matching your monitoring profile:</p>
                    
                    <div style="background-color:#f1f5f9;border-left:4px solid ${color};padding:24px;border-radius:8px;margin-bottom:24px;">
                      <table width="100%" border="0" cellspacing="0" cellpadding="0">
                        <tr><td style="padding-bottom:8px;font-size:12px;color:#94a3b8;text-transform:uppercase;font-weight:700;">Indicator</td></tr>
                        <tr><td style="padding-bottom:16px;font-family:monospace;font-size:18px;color:#0f172a;font-weight:600;">${indicator.indicator}</td></tr>
                        <tr>
                          <td>
                            <table width="100%" border="0" cellspacing="0" cellpadding="0">
                              <tr>
                                <td width="50%" style="padding-bottom:16px;">
                                  <div style="font-size:11px;color:#94a3b8;text-transform:uppercase;font-weight:700;margin-bottom:4px;">Type</div>
                                  <div style="font-size:14px;color:#334155;font-weight:600;">${(indicator.type||'').toUpperCase()}</div>
                                </td>
                                <td width="50%" style="padding-bottom:16px;">
                                  <div style="font-size:11px;color:#94a3b8;text-transform:uppercase;font-weight:700;margin-bottom:4px;">Risk Score</div>
                                  <div style="font-size:14px;color:${color};font-weight:800;">${indicator.risk_score}/100</div>
                                </td>
                              </tr>
                            </table>
                          </td>
                        </tr>
                        <tr><td style="padding-bottom:8px;font-size:12px;color:#94a3b8;text-transform:uppercase;font-weight:700;">Reason for Alert</td></tr>
                        <tr><td style="font-size:14px;color:#475569;line-height:1.5;">${reason}</td></tr>
                      </table>
                    </div>

                    <p style="margin:0 0 32px 0;font-size:14px;color:#64748b;">Please investigate this indicator immediately within your ThreatView dashboard.</p>
                    
                    <table border="0" cellspacing="0" cellpadding="0">
                      <tr>
                        <td align="center" bgcolor="#6366f1" style="border-radius:8px;">
                          <a href="http://localhost:5173" target="_blank" style="padding:14px 32px;font-size:16px;color:#ffffff;text-decoration:none;font-weight:600;display:inline-block;">View in Dashboard</a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td style="background-color:#f8fafc;padding:24px;text-align:center;border-top:1px solid #e2e8f0;">
                    <div style="font-size:12px;color:#94a3b8;">ThreatView Intelligence Platform &bull; Automated Security Alert</div>
                    <div style="font-size:11px;color:#cbd5e1;margin-top:4px;">Do not reply to this email. To manage alerts, visit your settings page.</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
    </html>
    `;
  }
  _buildAlertEmailText(user, indicator, reason) {
    return `🚨 THREATVIEW ALERT\n\nHi ${user.name || user.email},\nA new threat has been detected matching your profile:\n\nIndicator: ${indicator.indicator}\nRisk Score: ${indicator.risk_score}/100\nReason: ${reason}\n\nPlease review in your dashboard: http://localhost:5173`;
  }
  _buildSummaryEmail(user, summary) {
    return `
    <html>
      <body style="margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;background-color:#f8fafc;">
        <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color:#f8fafc;padding:40px 20px;">
          <tr>
            <td align="center">
              <table width="600" border="0" cellspacing="0" cellpadding="0" style="background-color:#ffffff;border-radius:16px;border:1px solid #e2e8f0;">
                <tr>
                  <td style="background-color:#0f172a;padding:32px;text-align:center;">
                    <h1 style="margin:0;color:#ffffff;font-size:24px;font-weight:800;letter-spacing:0.05em;text-transform:uppercase;">ThreatView</h1>
                    <div style="color:rgba(255,255,255,0.6);font-size:14px;margin-top:4px;">Daily Intelligence Digest</div>
                  </td>
                </tr>
                <tr>
                  <td style="padding:40px;">
                    <h2 style="margin:0 0 24px 0;font-size:20px;color:#0f172a;">Intelligence Summary</h2>
                    <table width="100%" border="0" cellspacing="0" cellpadding="0">
                      <tr>
                        <td width="50%" style="padding:0 8px 16px 0;">
                          <div style="background-color:#f1f5f9;padding:20px;border-radius:12px;text-align:center;">
                            <div style="font-size:28px;font-weight:800;color:#6366f1;">${summary.newIndicators}</div>
                            <div style="font-size:11px;color:#64748b;text-transform:uppercase;font-weight:700;margin-top:4px;">New Indicators</div>
                          </div>
                        </td>
                        <td width="50%" style="padding:0 0 16px 8px;">
                          <div style="background-color:#f1f5f9;padding:20px;border-radius:12px;text-align:center;">
                            <div style="font-size:28px;font-weight:800;color:#ef4444;">${summary.highRiskCount}</div>
                            <div style="font-size:11px;color:#64748b;text-transform:uppercase;font-weight:700;margin-top:4px;">High Risk Alerts</div>
                          </div>
                        </td>
                      </tr>
                    </table>
                    <p style="font-size:14px;color:#64748b;line-height:1.6;margin-top:16px;">Top threat regions detected today: <strong>${summary.topCountries}</strong></p>
                  </td>
                </tr>
                <tr>
                  <td style="background-color:#f8fafc;padding:24px;text-align:center;border-top:1px solid #e2e8f0;">
                    <div style="font-size:12px;color:#94a3b8;">&copy; ${new Date().getFullYear()} ThreatView Intelligence Platform</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
    </html>
    `;
  }
  _buildReportEmail(user, reportName) {
    return `
    <html>
      <body style="font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px;">
        <div style="max-width: 600px; background: white; margin: 0 auto; padding: 20px; border-radius: 8px;">
          <h2 style="color: #1976d2;">📋 Your Threat Report is Ready</h2>
          <p>Hi ${user.name || user.email},</p>
          <p>Your requested report <strong>"${reportName}"</strong> is attached and ready for review.</p>
          <p style="color: #666; font-size: 14px;">This report contains confidential threat intelligence and should be handled accordingly.</p>
          <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #999; font-size: 12px;">
            <p>ThreatView Security Intelligence Platform</p>
          </div>
        </div>
      </body>
    </html>
    `;
  }
  _riskColor(score) {
    if (score >= 80) return '#d32f2f';
    if (score >= 60) return '#f57c00';
    if (score >= 40) return '#fbc02d';
    return '#388e3c';
  }
}
module.exports = new EmailService();