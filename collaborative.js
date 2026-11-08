/**
 * Phishing Detection Platform - Collaborative Intelligence Engine
 * Module 5: Collaborative Intelligence (Crowdsourced Threat Reports, Community Voting & Shared Intel)
 */

class CollaborativeIntelligence {
  constructor() {
    this.storageKey = 'phishshield_community_reports_v2';
    this.votesStorageKey = 'phishshield_user_votes_v2';
    this.reports = [];
    this.userVotes = {};
    this.init();
  }

  init() {
    this.loadVotes();
    this.loadReports();
  }

  loadVotes() {
    try {
      const savedVotes = localStorage.getItem(this.votesStorageKey);
      this.userVotes = savedVotes ? JSON.parse(savedVotes) : {};
    } catch (e) {
      this.userVotes = {};
    }
  }

  saveVotes() {
    try {
      localStorage.setItem(this.votesStorageKey, JSON.stringify(this.userVotes));
    } catch (e) {
      console.warn('Failed to save votes to localStorage', e);
    }
  }

  loadReports() {
    try {
      const stored = localStorage.getItem(this.storageKey);
      if (stored) {
        this.reports = JSON.parse(stored);
      } else {
        this.reports = this.getSeedReports();
        this.saveReports();
      }
    } catch (e) {
      this.reports = this.getSeedReports();
    }
  }

  saveReports() {
    try {
      localStorage.setItem(this.storageKey, JSON.stringify(this.reports));
    } catch (e) {
      console.warn('Failed to save reports to localStorage', e);
    }
  }

  getSeedReports() {
    return [
      {
        id: 'rep-101',
        url: 'http://secure-login-chase-update.bank-verification.xyz/auth',
        category: 'Credential Harvester',
        targetBrand: 'Chase Bank',
        severity: 'Critical',
        reportedBy: 'CyberSec_Analyst_BD',
        timestamp: new Date(Date.now() - 3600000 * 3).toISOString(),
        description: 'Fake Chase banking portal attempting to harvest online banking passwords and OTP tokens via fake SMS lures.',
        votesConfirm: 42,
        votesFalsePositive: 1,
        verified: true,
        source: 'Community Intel'
      },
      {
        id: 'rep-102',
        url: 'http://192.168.1.100/paypal/login.php?update=account',
        category: 'Phishing',
        targetBrand: 'PayPal',
        severity: 'Critical',
        reportedBy: 'Rahim_EthicalHacker',
        timestamp: new Date(Date.now() - 3600000 * 8).toISOString(),
        description: 'Raw IP hosting an exact replica of PayPal payment confirmation page with stolen logo assets.',
        votesConfirm: 31,
        votesFalsePositive: 0,
        verified: true,
        source: 'Automated Bot Detection'
      },
      {
        id: 'rep-103',
        url: 'http://appleid.apple.com.manage-security-signin.click/verify',
        category: 'Credential Harvester',
        targetBrand: 'Apple',
        severity: 'Critical',
        reportedBy: 'Tanzil_Security',
        timestamp: new Date(Date.now() - 3600000 * 18).toISOString(),
        description: 'Subdomain deception mimicking Apple ID 2FA lock screen, sent via phishing iMessage alerts.',
        votesConfirm: 56,
        votesFalsePositive: 2,
        verified: true,
        source: 'Community Intel'
      },
      {
        id: 'rep-104',
        url: 'http://free-crypto-giveaway-binance.top/claim',
        category: 'Fake Crypto / Scam',
        targetBrand: 'Binance',
        severity: 'High',
        reportedBy: 'CryptoGuardian',
        timestamp: new Date(Date.now() - 3600000 * 32).toISOString(),
        description: 'Promises 2x Bitcoin / BNB return if user connects their Web3 wallet. Malicious drainage smart contract.',
        votesConfirm: 27,
        votesFalsePositive: 0,
        verified: true,
        source: 'Community Intel'
      },
      {
        id: 'rep-105',
        url: 'https://github.com',
        category: 'Verified Safe',
        targetBrand: 'GitHub',
        severity: 'Safe',
        reportedBy: 'System',
        timestamp: new Date(Date.now() - 3600000 * 120).toISOString(),
        description: 'Official developer collaboration platform with EV SSL and Strict HSTS.',
        votesConfirm: 89,
        votesFalsePositive: 0,
        verified: true,
        source: 'Official Whitelist'
      }
    ];
  }

  /**
   * Submit a new threat report
   */
  submitReport(reportData) {
    const newReport = {
      id: 'rep-' + Date.now().toString(36) + Math.random().toString(36).substr(2, 4),
      url: reportData.url.trim(),
      category: reportData.category || 'Phishing',
      targetBrand: reportData.targetBrand || 'Unknown Brand',
      severity: reportData.severity || 'High',
      reportedBy: reportData.reportedBy || 'Anonymous Contributor',
      timestamp: new Date().toISOString(),
      description: reportData.description || 'User submitted threat report via platform.',
      votesConfirm: 1,
      votesFalsePositive: 0,
      verified: false,
      source: 'User Submission'
    };

    // Prepend to top of reports
    this.reports.unshift(newReport);
    this.saveReports();
    return newReport;
  }

  /**
   * Check if a URL matches any reported threats
   */
  lookupUrl(url) {
    if (!url) return null;
    const cleanSearch = url.toLowerCase().replace(/^https?:\/\//, '').replace(/\/+$/, '');
    return this.reports.find(r => {
      const reportClean = r.url.toLowerCase().replace(/^https?:\/\//, '').replace(/\/+$/, '');
      return reportClean === cleanSearch || reportClean.includes(cleanSearch) || cleanSearch.includes(reportClean);
    });
  }

  /**
   * Vote on a report
   */
  vote(reportId, voteType) {
    const report = this.reports.find(r => r.id === reportId);
    if (!report) return null;

    const previousVote = this.userVotes[reportId];
    if (previousVote === voteType) {
      // Toggle off
      if (voteType === 'confirm') report.votesConfirm = Math.max(0, report.votesConfirm - 1);
      if (voteType === 'falsePositive') report.votesFalsePositive = Math.max(0, report.votesFalsePositive - 1);
      delete this.userVotes[reportId];
    } else {
      // If previously voted the other way, decrement that one
      if (previousVote === 'confirm') report.votesConfirm = Math.max(0, report.votesConfirm - 1);
      if (previousVote === 'falsePositive') report.votesFalsePositive = Math.max(0, report.votesFalsePositive - 1);

      // Add new vote
      if (voteType === 'confirm') report.votesConfirm++;
      if (voteType === 'falsePositive') report.votesFalsePositive++;
      this.userVotes[reportId] = voteType;
    }

    // Auto verify if confirmations exceed threshold
    if (report.votesConfirm >= 5 && report.votesConfirm > report.votesFalsePositive * 3) {
      report.verified = true;
    }

    this.saveReports();
    this.saveVotes();
    return report;
  }

  /**
   * Export reports as JSON file
   */
  exportJSON() {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(this.reports, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `phishing_threat_intelligence_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  }

  /**
   * Export reports as CSV file
   */
  exportCSV() {
    const headers = ['ID', 'URL', 'Category', 'Target Brand', 'Severity', 'Reported By', 'Timestamp', 'Confirm Votes', 'Verified'];
    const rows = this.reports.map(r => [
      r.id,
      `"${r.url.replace(/"/g, '""')}"`,
      `"${r.category}"`,
      `"${r.targetBrand}"`,
      r.severity,
      `"${r.reportedBy}"`,
      r.timestamp,
      r.votesConfirm,
      r.verified ? 'Yes' : 'No'
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", encodedUri);
    downloadAnchor.setAttribute("download", `threat_feed_${Date.now()}.csv`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  }

  /**
   * Get stats overview
   */
  getStats() {
    const total = this.reports.length;
    const verified = this.reports.filter(r => r.verified).length;
    const critical = this.reports.filter(r => r.severity === 'Critical').length;
    const totalVotes = this.reports.reduce((acc, r) => acc + r.votesConfirm + r.votesFalsePositive, 0);

    return {
      total,
      verified,
      critical,
      totalVotes
    };
  }
}

// Export singleton instance
window.collaborativeIntel = new CollaborativeIntelligence();
