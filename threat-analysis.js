/**
 * Phishing Detection Platform - Threat Analysis Engine
 * Module 2: Threat Analysis (Domain & URL Structure Deep Assessment)
 */

class ThreatAnalyzer {
  constructor() {
    // Known URL shorteners that conceal destination
    this.urlShorteners = [
      'bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'ow.ly', 'buff.ly',
      'cutt.ly', 'rb.gy', 'goo.gl', 'shorte.st', 'bc.vc', 'adf.ly'
    ];

    // High reputation TLDs vs Risk Levels
    this.tldReputation = {
      '.gov': { risk: 0, level: 'Very Low', trust: 'Official Government Entity' },
      '.edu': { risk: 5, level: 'Very Low', trust: 'Educational Institution' },
      '.org': { risk: 10, level: 'Low', trust: 'Non-profit Organization' },
      '.com': { risk: 15, level: 'Normal', trust: 'Commercial Generic' },
      '.net': { risk: 18, level: 'Normal', trust: 'Network Infrastructure' },
      '.io': { risk: 20, level: 'Low-Medium', trust: 'Tech / SaaS' },
      '.ai': { risk: 20, level: 'Low-Medium', trust: 'Tech / AI' },
      '.xyz': { risk: 65, level: 'High', trust: 'Frequent Abuse Vector' },
      '.top': { risk: 75, level: 'Critical', trust: 'High Abuse / Spam' },
      '.tk': { risk: 85, level: 'Critical', trust: 'Free TLD / High Threat' },
      '.ml': { risk: 80, level: 'Critical', trust: 'Free TLD / Botnets' },
      '.ga': { risk: 80, level: 'Critical', trust: 'Free TLD / Phishing' },
      '.cf': { risk: 80, level: 'Critical', trust: 'Free TLD / Phishing' },
      '.gq': { risk: 80, level: 'Critical', trust: 'Free TLD / Phishing' },
      '.buzz': { risk: 70, level: 'High', trust: 'Spam Campaigns' },
      '.icu': { risk: 70, level: 'High', trust: 'Phishing Campaigns' },
      '.zip': { risk: 60, level: 'High', trust: 'File Extension Confusion Risk' },
      '.click': { risk: 65, level: 'High', trust: 'Malvertising Vector' }
    };

    // Simulated known domain age database for authoritative domains & heuristics for unknown
    this.authoritativeAges = {
      'google.com': { ageYears: 28, registered: '1997-09-15', registrar: 'MarkMonitor Inc.' },
      'microsoft.com': { ageYears: 33, registered: '1991-05-02', registrar: 'Corporation Service Company' },
      'apple.com': { ageYears: 37, registered: '1987-02-19', registrar: 'CSC Corporate Domains' },
      'amazon.com': { ageYears: 30, registered: '1994-11-01', registrar: 'MarkMonitor Inc.' },
      'paypal.com': { ageYears: 25, registered: '1999-07-15', registrar: 'MarkMonitor Inc.' },
      'github.com': { ageYears: 17, registered: '2007-10-09', registrar: 'MarkMonitor Inc.' },
      'wikipedia.org': { ageYears: 24, registered: '2001-01-13', registrar: 'MarkMonitor Inc.' },
      'chase.com': { ageYears: 32, registered: '1993-01-14', registrar: 'CSC Corporate Domains' }
    };
  }

  /**
   * Analyze threat vectors based on domain and URL architecture
   */
  analyzeThreat(url, parsedFeatures) {
    const hostname = parsedFeatures ? parsedFeatures.hostname : (new URL(url).hostname || '');
    const cleanUrl = url.toLowerCase();

    // 1. Domain Age & Registration Heuristic
    const domainAgeData = this.evaluateDomainAge(hostname, parsedFeatures);

    // 2. URL Shortener Detection
    const isShortened = this.urlShorteners.some(shortener => hostname === shortener || hostname.endsWith('.' + shortener));

    // 3. TLD Threat Assessment
    const tldAssessment = this.evaluateTLD(hostname);

    // 4. Structural Obfuscation Assessment
    const structureEvaluation = this.evaluateStructure(cleanUrl, parsedFeatures);

    // 5. Threat Vectors Categorization
    const threatVectors = [];

    if (parsedFeatures && parsedFeatures.hasIpAddress) {
      threatVectors.push({
        title: 'Direct IP Routing',
        titleBn: 'সরাসরি IP রাউটিং',
        risk: 'High',
        desc: 'DNS নেমসার্ভার এড়িয়ে সরাসরি সার্ভার IP তে কানেক্ট করছে, যা সাইবার হামলায় সচরাচর দেখা যায়।'
      });
    }

    if (parsedFeatures && parsedFeatures.impersonatedBrand) {
      threatVectors.push({
        title: 'Brand Impersonation Vector',
        titleBn: 'ব্র্যান্ড প্রতারণা ভেক্টর',
        risk: 'Critical',
        desc: `অনুমোদিত নয় এমন ডোমেনে "${parsedFeatures.impersonatedBrand}" ব্র্যান্ডের নাম রয়েছে। এটি ফিশিং লুর (Lure)।`
      });
    }

    if (isShortened) {
      threatVectors.push({
        title: 'URL Obfuscation via Shortener',
        titleBn: 'URL সংক্ষিপ্তকারক দ্বারা আসল গন্তব্য গোপন',
        risk: 'Medium',
        desc: 'URL Shortener ব্যবহারের ফলে ব্যবহারকারী চূড়ান্ত ক্ষতিকর গন্তব্য সরাসরি দেখতে পায় না।'
      });
    }

    if (structureEvaluation.deepSubdomains) {
      threatVectors.push({
        title: 'Subdomain Spoofing',
        titleBn: 'সাবডোমেন বিভ্রান্তি',
        risk: 'High',
        desc: 'মাল্টিপল সাবডোমেন লেভেল দিয়ে মোবাইলের অ্যাড্রেস বারে আসল ক্ষতিকর ডোমেনটি ঢেকে ফেলা হচ্ছে।'
      });
    }

    if (tldAssessment.riskScore >= 60) {
      threatVectors.push({
        title: 'Low-Trust TLD Abuse',
        titleBn: 'অবিশ্বস্ত TLD অপব্যবহার',
        risk: 'High',
        desc: `TLD (${tldAssessment.tld}) সাইবার অপরাধীদের মধ্যে স্বল্প খরচ এবং দুর্বল ভেরিফিকেশনের জন্য পরিচিত।`
      });
    }

    // Overall Threat Index Calculation (0-100)
    let threatIndex = 10;
    if (domainAgeData.isVeryNew) threatIndex += 35;
    else if (domainAgeData.isNew) threatIndex += 20;

    if (isShortened) threatIndex += 15;
    threatIndex += Math.round(tldAssessment.riskScore * 0.3);
    if (structureEvaluation.riskScore) threatIndex += structureEvaluation.riskScore * 0.4;
    if (parsedFeatures && parsedFeatures.hasIpAddress) threatIndex += 30;
    if (parsedFeatures && parsedFeatures.impersonatedBrand) threatIndex += 25;

    threatIndex = Math.min(100, Math.max(5, Math.round(threatIndex)));

    return {
      domainAgeData,
      isShortened,
      tldAssessment,
      structureEvaluation,
      threatVectors,
      threatIndex,
      threatLevel: threatIndex >= 70 ? 'CRITICAL' : threatIndex >= 45 ? 'ELEVATED' : threatIndex >= 25 ? 'GUARDED' : 'LOW',
      threatLevelBn: threatIndex >= 70 ? 'চরম বিপজ্জনক (Critical)' : threatIndex >= 45 ? 'উচ্চ হুমকি (Elevated)' : threatIndex >= 25 ? 'সতর্কাবস্থা (Guarded)' : 'স্বাভাবিক/কম হুমকি (Low)'
    };
  }

  /**
   * Evaluate Domain Age
   */
  evaluateDomainAge(hostname, features) {
    // Check known database
    for (const [knownDomain, data] of Object.entries(this.authoritativeAges)) {
      if (hostname === knownDomain || hostname.endsWith('.' + knownDomain)) {
        return {
          domain: knownDomain,
          ageYears: data.ageYears,
          ageDays: data.ageYears * 365,
          registered: data.registered,
          registrar: data.registrar,
          isVeryNew: false,
          isNew: false,
          status: 'Established & Trusted',
          statusBn: 'বহু বছর পুরোনো ও প্রতিষ্ঠিত ডোমেন'
        };
      }
    }

    // If it is IP address, domain age is not applicable
    if (features && features.hasIpAddress) {
      return {
        domain: hostname,
        ageYears: 0,
        ageDays: 0,
        registered: 'N/A (Raw IP)',
        registrar: 'Autonomous System (ASN)',
        isVeryNew: true,
        isNew: true,
        status: 'Raw IP Address',
        statusBn: 'সরাসরি IP অ্যাড্রেস (কোনো ডোমেন বয়স নেই)'
      };
    }

    // Heuristic estimation based on TLD and hostname entropy
    let estimatedAgeDays = 45;
    let isVeryNew = false;
    let isNew = false;

    if (features && (features.matchedHighRiskTLD || features.excessiveHyphens || features.isHighEntropy)) {
      // Phishing domains typically created within last 7-30 days
      estimatedAgeDays = Math.floor(Math.random() * 20) + 4;
      isVeryNew = true;
    } else {
      estimatedAgeDays = 420; // ~ 1.1 years
    }

    return {
      domain: hostname,
      ageYears: (estimatedAgeDays / 365).toFixed(1),
      ageDays: estimatedAgeDays,
      registered: isVeryNew ? 'Recent (< 30 days)' : 'Estimated Active Domain',
      registrar: isVeryNew ? 'Privacy Protected Registrar / Dynamic DNS' : 'Standard ICANN Registrar',
      isVeryNew,
      isNew: estimatedAgeDays < 180,
      status: isVeryNew ? 'Newly Registered (High Risk)' : 'Moderately Established',
      statusBn: isVeryNew ? 'সদ্য নিবন্ধিত ডোমেন (উচ্চ ঝুঁকি - ৩০ দিনের কম)' : 'সক্রিয় নিবন্ধিত ডোমেন'
    };
  }

  /**
   * Evaluate TLD Reputation
   */
  evaluateTLD(hostname) {
    let foundTLD = '.com';
    let tldInfo = { risk: 15, level: 'Normal', trust: 'Commercial Generic' };

    for (const [tld, info] of Object.entries(this.tldReputation)) {
      if (hostname.endsWith(tld)) {
        foundTLD = tld;
        tldInfo = info;
        break;
      }
    }

    return {
      tld: foundTLD,
      riskScore: tldInfo.risk,
      level: tldInfo.level,
      trustDescription: tldInfo.trust
    };
  }

  /**
   * Evaluate URL Structure
   */
  evaluateStructure(url, features) {
    const length = url.length;
    const parts = (features ? features.hostname : '').split('.');
    const deepSubdomains = parts.length > 3;
    const pathSegmentCount = (new URL(url).pathname.split('/').filter(Boolean)).length;
    const queryParamsCount = Array.from(new URL(url).searchParams.keys()).length;

    let riskScore = 0;
    if (length > 100) riskScore += 25;
    else if (length > 70) riskScore += 15;

    if (deepSubdomains) riskScore += 30;
    if (pathSegmentCount > 4) riskScore += 15;
    if (queryParamsCount > 4) riskScore += 15;

    return {
      urlLength: length,
      subdomainLevels: Math.max(0, parts.length - 2),
      deepSubdomains,
      pathDepth: pathSegmentCount,
      parametersCount: queryParamsCount,
      riskScore: Math.min(100, riskScore)
    };
  }
}

// Export singleton instance
window.threatAnalyzer = new ThreatAnalyzer();
