/**
 * Phishing Detection Platform - Main Application Controller
 * Coordinates all 5 modules, UI rendering, language toggle, and scanning workflow.
 */

class AppController {
  constructor() {
    this.currentLanguage = 'bn'; // Default to Bengali as requested by user
    this.currentTab = 'scanner';
    this.currentScanResult = null;
    this.threatChart = null;

    // Translations Dictionary (Bengali & English)
    this.translations = {
      bn: {
        appTitle: 'ফিশিং ডিটেকশন ও থ্রেট ইন্টেলিজেন্স প্ল্যাটফর্ম',
        appSubtitle: 'AI, হিউরিস্টিক এবং রিয়েল-টাইম থ্রেট অ্যানালাইসিস দিয়ে সুরক্ষিত থাকুন',
        tabScanner: 'ইউআরএল স্ক্যানার',
        tabPhishing: '১. ফিশিং ডিটেকশন',
        tabThreat: '২. থ্রেট অ্যানালাইসিস',
        tabSSL: '৩. SSL/TLS ভ্যালিডেশন',
        tabSecurity: '৪. ওয়েব সিকিউরিটি',
        tabCommunity: '৫. কোলাবোরেটিভ ইন্টেলিজেন্স',
        tabEducation: 'সচেতনতা ও কুইজ',
        scanInputPlaceholder: 'পরীক্ষা করার জন্য যেকোনো ওয়েবসাইট বা URL প্রবেশ করান (যেমন: http://paypal-secure.xyz)...',
        btnScan: 'স্ক্যান ও বিশ্লেষণ করুন',
        btnScanning: 'বিশ্লেষণ চলছে...',
        sampleHeader: 'বাস্তবধর্মী ডেমো URL পরীক্ষা করে দেখুন:',
        sampleSafeGoogle: 'গুগল (নিরাপদ)',
        sampleSafeGithub: 'গিটহাব (নিরাপদ)',
        samplePhishChase: 'ব্যাংক ফিশিং (ঝুঁকিপূর্ণ)',
        samplePhishIP: 'আইপি ফিশিং (ঝুঁকিপূর্ণ)',
        samplePhishApple: 'অ্যাপল ক্রেডেনশিয়াল ফিশিং',
        recentThreatsTitle: 'সাম্প্রতিক কমিউনিটি থ্রেট অ্যালার্ট:',
        reportThreatBtn: '+ নতুন ক্ষতিকর URL রিপোর্ট করুন',
        exportJsonBtn: 'JSON ডাউনলোড',
        exportCsvBtn: 'CSV ডাউনলোড',
        filterAll: 'সকল ক্যাটাগরি',
        searchPlaceholder: 'রিপোর্টের মধ্যে URL বা ব্র্যান্ড খুঁজুন...',
        noResultsFound: 'কোনো রিপোর্ট পাওয়া যায়নি।'
      },
      en: {
        appTitle: 'Phishing Detection & Threat Intelligence Platform',
        appSubtitle: 'Protecting users with AI, Deep Heuristics and Real-time Threat Analysis',
        tabScanner: 'URL Scanner',
        tabPhishing: '1. Phishing Detection',
        tabThreat: '2. Threat Analysis',
        tabSSL: '3. SSL/TLS Validation',
        tabSecurity: '4. Web Security',
        tabCommunity: '5. Collaborative Intel',
        tabEducation: 'Awareness & Quiz',
        scanInputPlaceholder: 'Enter any website or URL to inspect (e.g. http://paypal-secure.xyz)...',
        btnScan: 'Scan & Analyze Now',
        btnScanning: 'Analyzing...',
        sampleHeader: 'Test with realistic sample URLs:',
        sampleSafeGoogle: 'Google (Safe)',
        sampleSafeGithub: 'GitHub (Safe)',
        samplePhishChase: 'Bank Phishing (High Risk)',
        samplePhishIP: 'Raw IP Phishing (High Risk)',
        samplePhishApple: 'Apple ID Phishing',
        recentThreatsTitle: 'Recent Community Threat Alerts:',
        reportThreatBtn: '+ Report Malicious URL',
        exportJsonBtn: 'Export JSON',
        exportCsvBtn: 'Export CSV',
        filterAll: 'All Categories',
        searchPlaceholder: 'Search reports by URL or brand...',
        noResultsFound: 'No reports found.'
      }
    };
  }

  init() {
    this.setupEventListeners();
    this.renderCommunityFeed();
    this.renderTicker();
    this.updateStatsCounters();
    this.applyLanguage();

    // Run an initial scan on a sample phishing URL so the user sees immediate rich data
    this.scanUrl('http://secure-login-chase-update.bank-verification.xyz/auth?user=victim@domain.com');
  }

  setupEventListeners() {
    // Tab switching
    document.querySelectorAll('.nav-tab').forEach(tab => {
      tab.addEventListener('click', (e) => {
        const targetTab = e.currentTarget.getAttribute('data-tab');
        this.switchTab(targetTab);
      });
    });

    // Language toggle
    const langBtn = document.getElementById('langToggleBtn');
    if (langBtn) {
      langBtn.addEventListener('click', () => {
        this.currentLanguage = this.currentLanguage === 'bn' ? 'en' : 'bn';
        this.applyLanguage();
        if (this.currentScanResult) {
          this.renderScanResults(this.currentScanResult);
        }
      });
    }

    // Scan form submit
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
      scanForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const input = document.getElementById('urlInput');
        if (input && input.value.trim()) {
          this.scanUrl(input.value.trim());
        }
      });
    }

    // Sample buttons
    document.querySelectorAll('.sample-url-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const url = e.currentTarget.getAttribute('data-url');
        const input = document.getElementById('urlInput');
        if (input) input.value = url;
        this.scanUrl(url);
      });
    });

    // Report Threat Modal controls
    const openModalBtn = document.getElementById('openReportModalBtn');
    const closeModalBtn = document.getElementById('closeReportModalBtn');
    const reportModal = document.getElementById('reportModal');
    const reportForm = document.getElementById('reportThreatForm');

    if (openModalBtn && reportModal) {
      openModalBtn.addEventListener('click', () => {
        reportModal.classList.remove('hidden');
      });
    }

    if (closeModalBtn && reportModal) {
      closeModalBtn.addEventListener('click', () => {
        reportModal.classList.add('hidden');
      });
    }

    if (reportForm) {
      reportForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const url = document.getElementById('reportUrl').value;
        const category = document.getElementById('reportCategory').value;
        const targetBrand = document.getElementById('reportBrand').value;
        const severity = document.getElementById('reportSeverity').value;
        const reportedBy = document.getElementById('reportUser').value;
        const description = document.getElementById('reportDesc').value;

        window.collaborativeIntel.submitReport({
          url,
          category,
          targetBrand,
          severity,
          reportedBy,
          description
        });

        reportForm.reset();
        if (reportModal) reportModal.classList.add('hidden');
        this.renderCommunityFeed();
        this.renderTicker();
        this.updateStatsCounters();
        this.showToast('থ্রেট রিপোর্ট সফলভাবে কমিউনিটিতে যুক্ত হয়েছে!', 'success');
      });
    }

    // Community Search and Filter
    const searchInput = document.getElementById('communitySearchInput');
    const categoryFilter = document.getElementById('communityCategoryFilter');

    if (searchInput) {
      searchInput.addEventListener('input', () => this.filterCommunityReports());
    }
    if (categoryFilter) {
      categoryFilter.addEventListener('change', () => this.filterCommunityReports());
    }

    // Export Buttons
    const exportJson = document.getElementById('exportJsonBtn');
    const exportCsv = document.getElementById('exportCsvBtn');

    if (exportJson) {
      exportJson.addEventListener('click', () => window.collaborativeIntel.exportJSON());
    }
    if (exportCsv) {
      exportCsv.addEventListener('click', () => window.collaborativeIntel.exportCSV());
    }
  }

  switchTab(tabId) {
    this.currentTab = tabId;
    document.querySelectorAll('.nav-tab').forEach(tab => {
      if (tab.getAttribute('data-tab') === tabId) {
        tab.classList.add('active');
      } else {
        tab.classList.remove('active');
      }
    });

    document.querySelectorAll('.tab-content').forEach(section => {
      if (section.id === `tab-${tabId}`) {
        section.classList.remove('hidden');
      } else {
        section.classList.add('hidden');
      }
    });
  }

  applyLanguage() {
    const t = this.translations[this.currentLanguage];
    const langBadge = document.getElementById('currentLangBadge');
    if (langBadge) {
      langBadge.textContent = this.currentLanguage === 'bn' ? 'বাংলা' : 'EN';
    }

    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      if (t[key]) {
        if (el.tagName === 'INPUT' && el.getAttribute('placeholder')) {
          el.setAttribute('placeholder', t[key]);
        } else {
          el.textContent = t[key];
        }
      }
    });
  }

  /**
   * Run full multi-module analysis on a target URL
   */
  async scanUrl(url) {
    const scanBtn = document.getElementById('scanSubmitBtn');
    const scanStatus = document.getElementById('scanProgressContainer');
    const resultsContainer = document.getElementById('scanResultsContainer');

    // UI Loading state
    if (scanBtn) {
      scanBtn.disabled = true;
      scanBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-2"></i> ${this.translations[this.currentLanguage].btnScanning}`;
    }
    if (scanStatus) scanStatus.classList.remove('hidden');

    // Progressive simulated security scanning steps for high realism
    const progressText = document.getElementById('scanProgressStep');
    const progressBar = document.getElementById('scanProgressBar');

    const steps = [
      { text: 'URL সিনট্যাক্স ও লেক্সিক্যাল বিশ্লেষণ চলছে...', pct: 20 },
      { text: 'AI ও হিউরিস্টিক ফিশিং ফিচার এক্সট্রাকশন...', pct: 40 },
      { text: 'ডোমেন বয়স ও থ্রেট ভেক্টর মূল্যায়ন...', pct: 60 },
      { text: 'SSL/TLS সার্টিফিকেট ও সিফার স্যুট ভ্যালিডেশন...', pct: 80 },
      { text: 'কমিউনিটি ইন্টেলিজেন্স ও সিকিউরিটি হেডার অডিট...', pct: 100 }
    ];

    for (const step of steps) {
      if (progressText) progressText.textContent = step.text;
      if (progressBar) progressBar.style.width = `${step.pct}%`;
      await new Promise(r => setTimeout(r, 140));
    }

    // 1. Phishing Detection Engine
    const phishingResult = window.phishingDetector.analyze(url);

    // 2. Threat Analysis Engine
    const threatResult = window.threatAnalyzer.analyzeThreat(url, phishingResult.features);

    // 3. SSL/TLS Validation Engine
    const sslResult = window.sslValidator.validateSSL(url, phishingResult.features);

    // 4. Web Security Assessment Engine
    const securityResult = window.webSecurityAssessor.assessSecurity(url, phishingResult.features);

    // 5. Collaborative Intelligence Lookup
    const communityMatch = window.collaborativeIntel.lookupUrl(url);

    // Combined Result Object
    this.currentScanResult = {
      url,
      timestamp: new Date(),
      phishing: phishingResult,
      threat: threatResult,
      ssl: sslResult,
      security: securityResult,
      communityMatch
    };

    // Render results
    this.renderScanResults(this.currentScanResult);

    // Reset button & hide progress
    if (scanBtn) {
      scanBtn.disabled = false;
      scanBtn.innerHTML = `<i class="fa-solid fa-magnifying-glass mr-2"></i> ${this.translations[this.currentLanguage].btnScan}`;
    }
    if (scanStatus) scanStatus.classList.add('hidden');
    if (resultsContainer) resultsContainer.classList.remove('hidden');
  }

  /**
   * Render all scan result views across the tabs
   */
  renderScanResults(res) {
    const isBn = this.currentLanguage === 'bn';
    const p = res.phishing;
    const t = res.threat;
    const s = res.ssl;
    const sec = res.security;

    // 1. Hero Verdict Card in Scanner Tab
    const verdictBanner = document.getElementById('mainVerdictBanner');
    const riskScoreVal = document.getElementById('mainRiskScoreVal');
    const riskConfidenceVal = document.getElementById('mainConfidenceVal');
    const mainVerdictTitle = document.getElementById('mainVerdictTitle');
    const mainVerdictDesc = document.getElementById('mainVerdictDesc');
    const gaugeCircle = document.getElementById('riskGaugeCircle');

    if (verdictBanner) {
      verdictBanner.className = 'glass-panel p-6 rounded-2xl relative overflow-hidden transition-all duration-300';
      if (p.riskScore >= 70) {
        verdictBanner.classList.add('border-red-500/60', 'bg-red-950/20', 'pulse-danger');
      } else if (p.riskScore >= 45) {
        verdictBanner.classList.add('border-amber-500/60', 'bg-amber-950/20');
      } else {
        verdictBanner.classList.add('border-emerald-500/60', 'bg-emerald-950/20');
      }
    }

    if (riskScoreVal) riskScoreVal.textContent = p.riskScore;
    if (riskConfidenceVal) riskConfidenceVal.textContent = `${p.confidence}%`;
    if (mainVerdictTitle) mainVerdictTitle.textContent = isBn ? p.verdictBengali : p.verdict;
    if (mainVerdictDesc) mainVerdictDesc.textContent = p.summary;

    // SVG Circular Gauge Animation
    if (gaugeCircle) {
      const radius = 45;
      const circumference = 2 * Math.PI * radius;
      const offset = circumference - (p.riskScore / 100) * circumference;
      gaugeCircle.style.strokeDasharray = `${circumference}`;
      gaugeCircle.style.strokeDashoffset = `${offset}`;
      
      if (p.riskScore >= 70) {
        gaugeCircle.style.stroke = '#ef4444';
      } else if (p.riskScore >= 45) {
        gaugeCircle.style.stroke = '#f59e0b';
      } else {
        gaugeCircle.style.stroke = '#10b981';
      }
    }

    // Community match alert badge
    const commAlert = document.getElementById('communityMatchAlert');
    if (commAlert) {
      if (res.communityMatch) {
        commAlert.classList.remove('hidden');
        commAlert.innerHTML = `
          <div class="p-3 bg-red-900/40 border border-red-500/40 rounded-xl flex items-center justify-between text-sm">
            <div class="flex items-center gap-3">
              <i class="fa-solid fa-triangle-exclamation text-red-400 text-lg"></i>
              <div>
                <strong class="text-red-300">কমিউনিটি রিপোর্ট মেলবন্ধন:</strong> এটি পূর্বেই 
                <span class="text-white font-mono">${res.communityMatch.reportedBy}</span> দ্বারা 
                <span class="text-red-400">${res.communityMatch.category}</span> হিসেবে চিহ্নিত করা হয়েছে।
              </div>
            </div>
            <span class="badge-critical text-xs px-2.5 py-1 rounded-full font-bold">
              ${res.communityMatch.votesConfirm} জন ব্যবহারকারী নিশ্চিত করেছেন
            </span>
          </div>
        `;
      } else {
        commAlert.classList.add('hidden');
      }
    }

    // Module Quick Summary Cards
    document.getElementById('quickPhishSummary').innerHTML = `
      <div class="text-2xl font-bold ${p.riskScore >= 70 ? 'text-red-400' : p.riskScore >= 45 ? 'text-amber-400' : 'text-emerald-400'}">
        ${p.riskScore}/100
      </div>
      <p class="text-xs text-slate-400 mt-1">${p.breakdown.length}টি ফিচার ফ্যাক্টর চিহ্নিত</p>
    `;

    document.getElementById('quickThreatSummary').innerHTML = `
      <div class="text-2xl font-bold ${t.threatIndex >= 60 ? 'text-red-400' : 'text-cyan-400'}">
        ${t.threatIndex}/100
      </div>
      <p class="text-xs text-slate-400 mt-1">${t.domainAgeData.statusBn}</p>
    `;

    document.getElementById('quickSSLSummary').innerHTML = `
      <div class="text-2xl font-bold ${s.hasSSL ? (s.isPhishingWithFreeSSL ? 'text-amber-400' : 'text-emerald-400') : 'text-red-400'}">
        ${s.statusBn.split(' ')[0]}
      </div>
      <p class="text-xs text-slate-400 mt-1">${s.protocol} (${s.issuer.split(' ')[0]})</p>
    `;

    document.getElementById('quickSecuritySummary').innerHTML = `
      <div class="text-2xl font-bold ${sec.gradeColor}">
        গ্রেড ${sec.grade}
      </div>
      <p class="text-xs text-slate-400 mt-1">${sec.headersPassedCount}/${sec.headersTotalCount} সিকিউরিটি হেডার সক্রিয়</p>
    `;

    // Recommendations list
    const recsList = document.getElementById('recommendationsList');
    if (recsList) {
      recsList.innerHTML = p.recommendations.map(r => `
        <li class="flex items-start gap-2 text-sm text-slate-300">
          <span>${r}</span>
        </li>
      `).join('');
    }

    // Render Tab 1: Phishing Feature Breakdown
    this.renderPhishingTab(p);

    // Render Tab 2: Threat Analysis Tab
    this.renderThreatTab(t, p.features);

    // Render Tab 3: SSL/TLS Validation Tab
    this.renderSSLTab(s);

    // Render Tab 4: Web Security Assessment Tab
    this.renderSecurityTab(sec);
  }

  renderPhishingTab(p) {
    const tableBody = document.getElementById('phishingFeaturesTableBody');
    if (!tableBody) return;

    if (p.breakdown.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="4" class="p-6 text-center text-emerald-400 text-sm">
            <i class="fa-solid fa-circle-check text-2xl mb-2"></i>
            <div>কোনো ক্ষতিকারক ফিশিং প্যাটার্ন বা হেউরিস্টিক ঝুঁকি মেলেনি। ডোমেনটি বৈধ।</div>
          </td>
        </tr>
      `;
      return;
    }

    tableBody.innerHTML = p.breakdown.map(item => `
      <tr class="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors">
        <td class="py-3 px-4 font-mono font-medium text-slate-200">${item.name}</td>
        <td class="py-3 px-4">
          <span class="px-2 py-0.5 rounded text-xs font-bold ${
            item.type === 'critical' ? 'badge-critical' : item.type === 'high' ? 'bg-orange-500/20 text-orange-400' : 'badge-warning'
          }">${item.type.toUpperCase()}</span>
        </td>
        <td class="py-3 px-4 text-red-400 font-mono font-bold">+${item.penalty} pts</td>
        <td class="py-3 px-4 text-xs text-slate-300">${item.detail}</td>
      </tr>
    `).join('');

    // Feature details grid
    document.getElementById('phishFeatureHostname').textContent = p.features.hostname || 'N/A';
    document.getElementById('phishFeatureEntropy').textContent = `${p.features.entropy} (Shannon Bits)`;
    document.getElementById('phishFeatureSubdomains').textContent = p.features.subdomainCount;
    document.getElementById('phishFeatureKeywords').textContent = p.features.matchedKeywords.length > 0 
      ? p.features.matchedKeywords.join(', ') 
      : 'None';
  }

  renderThreatTab(t, features) {
    document.getElementById('threatDomainAge').textContent = t.domainAgeData.statusBn;
    document.getElementById('threatRegistrar').textContent = t.domainAgeData.registrar;
    document.getElementById('threatTLDName').textContent = t.tldAssessment.tld;
    document.getElementById('threatTLDTrust').textContent = t.tldAssessment.trustDescription;
    document.getElementById('threatUrlLength').textContent = `${t.structureEvaluation.urlLength} Characters`;
    document.getElementById('threatPathDepth').textContent = `${t.structureEvaluation.pathDepth} Levels`;

    // Render threat vectors list
    const vectorContainer = document.getElementById('threatVectorsContainer');
    if (vectorContainer) {
      if (t.threatVectors.length === 0) {
        vectorContainer.innerHTML = `
          <div class="p-6 text-center text-slate-400 text-sm glass-panel rounded-xl">
            <i class="fa-solid fa-shield-halved text-emerald-400 text-2xl mb-2"></i>
            <div>কোনো মারাত্মক থ্রেট ভেক্টর শনাক্ত করা যায়নি।</div>
          </div>
        `;
      } else {
        vectorContainer.innerHTML = t.threatVectors.map(v => `
          <div class="glass-panel p-4 rounded-xl border-l-4 ${v.risk === 'Critical' ? 'border-l-red-500' : 'border-l-amber-500'}">
            <div class="flex items-center justify-between mb-1">
              <h4 class="font-bold text-slate-200 text-sm">${v.titleBn} (${v.title})</h4>
              <span class="text-xs px-2 py-0.5 rounded font-bold ${v.risk === 'Critical' ? 'badge-critical' : 'badge-warning'}">
                ${v.risk}
              </span>
            </div>
            <p class="text-xs text-slate-300 mt-1">${v.desc}</p>
          </div>
        `).join('');
      }
    }
  }

  renderSSLTab(s) {
    document.getElementById('sslStatusBadge').textContent = s.statusBn;
    document.getElementById('sslIssuerVal').textContent = s.issuer;
    document.getElementById('sslProtocolVal').textContent = s.protocol;
    document.getElementById('sslKeyStrengthVal').textContent = s.keyStrength;
    document.getElementById('sslCipherSuiteVal').textContent = s.cipherSuite;
    document.getElementById('sslDaysRemainingVal').textContent = s.daysRemaining > 0 ? `${s.daysRemaining} দিন অবশিষ্ট` : 'নেই';

    // Free SSL / Phishing Warning Banner
    const freeWarning = document.getElementById('sslPhishWarning');
    if (freeWarning) {
      if (s.isPhishingWithFreeSSL) {
        freeWarning.classList.remove('hidden');
      } else {
        freeWarning.classList.add('hidden');
      }
    }

    // Certificate Chain
    const chainContainer = document.getElementById('sslChainContainer');
    if (chainContainer) {
      chainContainer.innerHTML = s.certificateChain.map((node, index) => `
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 rounded-full flex items-center justify-center ${node.trusted ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'} font-bold text-xs">
            ${index + 1}
          </div>
          <div class="flex-1 glass-panel p-3 rounded-lg text-xs">
            <div class="text-slate-400 font-semibold uppercase text-[10px]">${node.level}</div>
            <div class="font-mono text-slate-200 mt-0.5">${node.name}</div>
          </div>
        </div>
      `).join('');
    }
  }

  renderSecurityTab(sec) {
    document.getElementById('secOverallGrade').textContent = sec.grade;
    document.getElementById('secOverallGrade').className = `text-4xl font-extrabold ${sec.gradeColor}`;
    document.getElementById('secGradeSummary').textContent = sec.gradeSummary;
    document.getElementById('secScoreVal').textContent = `${sec.totalScore}/100`;

    // Security Headers Table
    const headersTable = document.getElementById('securityHeadersTableBody');
    if (headersTable) {
      headersTable.innerHTML = sec.headers.map(h => `
        <tr class="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors">
          <td class="py-3 px-4 font-mono font-medium text-slate-200 text-xs">
            ${h.name}
            <div class="text-[11px] text-slate-400 font-sans mt-0.5">${h.desc}</div>
          </td>
          <td class="py-3 px-4">
            <span class="px-2 py-0.5 rounded text-xs font-bold ${h.isPresent ? 'badge-safe' : 'badge-critical'}">
              ${h.statusBn}
            </span>
          </td>
          <td class="py-3 px-4 font-mono text-[11px] text-slate-300 truncate max-w-[200px]" title="${h.value}">
            ${h.value}
          </td>
        </tr>
      `).join('');
    }

    // Additional Checks
    const additionalContainer = document.getElementById('securityAdditionalChecks');
    if (additionalContainer) {
      additionalContainer.innerHTML = sec.additionalChecks.map(c => `
        <div class="glass-panel p-3.5 rounded-xl flex items-center justify-between text-xs">
          <div>
            <div class="font-bold text-slate-200">${c.titleBn}</div>
            <div class="text-slate-400 mt-0.5">${c.detail}</div>
          </div>
          <i class="fa-solid ${c.passed ? 'fa-check text-emerald-400' : 'fa-xmark text-red-400'} text-lg ml-2"></i>
        </div>
      `).join('');
    }
  }

  /**
   * Collaborative Intelligence Rendering & Management
   */
  renderCommunityFeed(reportsToRender = null) {
    const list = reportsToRender || window.collaborativeIntel.reports;
    const container = document.getElementById('communityReportsList');
    if (!container) return;

    if (list.length === 0) {
      container.innerHTML = `
        <div class="p-8 text-center text-slate-400">
          <i class="fa-solid fa-inbox text-3xl mb-2 text-slate-500"></i>
          <div>${this.translations[this.currentLanguage].noResultsFound}</div>
        </div>
      `;
      return;
    }

    container.innerHTML = list.map(item => `
      <div class="glass-panel p-4 rounded-xl hover:border-cyan-500/30 transition-all duration-200">
        <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
          <div class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded text-xs font-bold ${
              item.severity === 'Critical' ? 'badge-critical' : item.severity === 'Safe' ? 'badge-safe' : 'badge-warning'
            }">
              ${item.severity}
            </span>
            <span class="text-xs bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-medium border border-slate-700">
              ${item.category}
            </span>
            ${item.verified ? '<span class="text-emerald-400 text-xs flex items-center gap-1"><i class="fa-solid fa-circle-check"></i> ভেরিফাইড থ্রেট</span>' : ''}
          </div>
          <div class="text-[11px] text-slate-400">
            <i class="fa-regular fa-clock mr-1"></i> ${new Date(item.timestamp).toLocaleDateString()}
          </div>
        </div>

        <div class="font-mono text-sm text-cyan-400 break-all select-all font-semibold mb-2">
          ${item.url}
        </div>

        <p class="text-xs text-slate-300 mb-3">${item.description}</p>

        <div class="flex items-center justify-between pt-2 border-t border-slate-800/80 text-xs">
          <div class="text-slate-400">
            টার্গেট: <strong class="text-slate-200">${item.targetBrand}</strong> | রিপোর্টকারী: <span class="font-mono text-slate-300">${item.reportedBy}</span>
          </div>
          <div class="flex items-center gap-2">
            <button onclick="window.appController.voteReport('${item.id}', 'confirm')" class="px-2.5 py-1 bg-red-950/40 hover:bg-red-900/60 border border-red-500/30 rounded text-red-300 flex items-center gap-1 transition-colors">
              <i class="fa-solid fa-thumbs-up"></i> নিশ্চিত (${item.votesConfirm})
            </button>
            <button onclick="window.appController.voteReport('${item.id}', 'falsePositive')" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-400 rounded transition-colors" title="ভুল রিপোর্ট">
              <i class="fa-solid fa-thumbs-down"></i> ${item.votesFalsePositive}
            </button>
            <button onclick="window.appController.loadUrlToScanner('${item.url}')" class="px-2.5 py-1 bg-cyan-950/40 hover:bg-cyan-900/60 border border-cyan-500/30 rounded text-cyan-300 flex items-center gap-1 transition-colors">
              <i class="fa-solid fa-magnifying-glass"></i> স্ক্যান
            </button>
          </div>
        </div>
      </div>
    `).join('');
  }

  loadUrlToScanner(url) {
    const input = document.getElementById('urlInput');
    if (input) input.value = url;
    this.switchTab('scanner');
    this.scanUrl(url);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  voteReport(reportId, type) {
    window.collaborativeIntel.vote(reportId, type);
    this.renderCommunityFeed();
    this.updateStatsCounters();
  }

  filterCommunityReports() {
    const search = (document.getElementById('communitySearchInput')?.value || '').toLowerCase();
    const category = document.getElementById('communityCategoryFilter')?.value || '';

    const filtered = window.collaborativeIntel.reports.filter(r => {
      const matchSearch = r.url.toLowerCase().includes(search) || 
                          r.targetBrand.toLowerCase().includes(search) ||
                          r.description.toLowerCase().includes(search);
      const matchCat = category === '' || r.category === category;
      return matchSearch && matchCat;
    });

    this.renderCommunityFeed(filtered);
  }

  renderTicker() {
    const ticker = document.getElementById('threatTickerContent');
    if (!ticker) return;

    const threats = window.collaborativeIntel.reports.slice(0, 8);
    const items = threats.map(t => `
      <span class="inline-flex items-center gap-2 mx-4 text-xs font-mono">
        <span class="w-2 h-2 rounded-full ${t.severity === 'Critical' ? 'bg-red-500 animate-ping' : 'bg-amber-400'}"></span>
        <span class="text-slate-400">[${t.category}]</span>
        <span class="text-red-400 font-bold truncate max-w-xs">${t.url}</span>
        <span class="text-slate-500">(${t.targetBrand})</span>
      </span>
    `).join(' • ');

    // Duplicate string for seamless infinite marquee loop
    ticker.innerHTML = items + ' • ' + items;
  }

  updateStatsCounters() {
    const stats = window.collaborativeIntel.getStats();
    const totalEl = document.getElementById('statTotalReports');
    const verifiedEl = document.getElementById('statVerifiedThreats');
    const votesEl = document.getElementById('statCommunityVotes');

    if (totalEl) totalEl.textContent = stats.total;
    if (verifiedEl) verifiedEl.textContent = stats.verified;
    if (votesEl) votesEl.textContent = stats.totalVotes;
  }

  showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `fixed bottom-5 right-5 z-50 px-4 py-3 rounded-xl shadow-2xl text-sm font-semibold flex items-center gap-2 transition-all duration-300 transform translate-y-2 ${
      type === 'success' ? 'bg-emerald-600 text-white' : 'bg-cyan-600 text-white'
    }`;
    toast.innerHTML = `<i class="fa-solid fa-circle-check"></i> ${message}`;
    document.body.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      setTimeout(() => toast.remove(), 400);
    }, 3000);
  }
}

// Global initialization
window.addEventListener('DOMContentLoaded', () => {
  window.appController = new AppController();
  window.appController.init();
});
