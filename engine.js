/**
 * Phishing Detection Platform - Machine Learning & Heuristic Phishing Engine
 * Module 1: Phishing Detection (AI & Machine Learning Heuristics)
 */

class PhishingDetector {
  constructor() {
    // Known suspicious keywords common in phishing lures
    this.suspiciousKeywords = [
      'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification',
      'authenticate', 'account', 'update', 'banking', 'secure', 'security',
      'confirm', 'password', 'credential', 'wallet', 'crypto', 'bonus',
      'free', 'reward', 'suspended', 'alert', 'support', 'helpdesk',
      'billing', 'invoice', 'payroll', 'tax-refund', 'claim', 'unlock',
      'ebayisapi', 'webscr', 'cmd=_login-run', 'oauth', 'token', 'recover'
    ];

    // High-risk and abuse-prone Top-Level Domains (TLDs)
    this.highRiskTLDs = [
      '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz',
      '.work', '.fit', '.rest', '.icu', '.zip', '.mov', '.click',
      '.loan', '.racing', '.download', '.accountant', '.country',
      '.stream', '.trade', '.bid', '.party', '.science'
    ];

    // Common brand targets for impersonation
    this.brandTargets = [
      { name: 'PayPal', patterns: ['paypal', 'paypa1', 'pay-pal', 'paypol', 'pypal'] },
      { name: 'Google', patterns: ['google', 'g00gle', 'googl', 'gmail', 'gmai1'] },
      { name: 'Microsoft', patterns: ['microsoft', 'micros0ft', 'micosoft', 'office365', 'outlook', 'live-login'] },
      { name: 'Apple', patterns: ['apple', 'appleid', 'icloud', 'app1e'] },
      { name: 'Amazon', patterns: ['amazon', 'amaz0n', 'amzn'] },
      { name: 'Netflix', patterns: ['netflix', 'netf1ix', 'net-flix'] },
      { name: 'Facebook/Meta', patterns: ['facebook', 'faceb00k', 'fb-login', 'meta-support', 'instagram'] },
      { name: 'Chase Bank', patterns: ['chase', 'chase-bank', 'chaseonline'] },
      { name: 'Bank of America', patterns: ['bankofamerica', 'bofa', 'bofa-login'] },
      { name: 'Binance', patterns: ['binance', 'binan-ce', 'binance-support'] },
      { name: 'MetaMask', patterns: ['metamask', 'meta-mask', 'metamask-wallet'] },
      { name: 'Steam', patterns: ['steampowered', 'steamcommunity', 'steam-gift'] }
    ];

    // Well-known legitimate domains
    this.whitelistedDomains = [
      'google.com', 'www.google.com', 'accounts.google.com', 'drive.google.com',
      'github.com', 'www.github.com', 'microsoft.com', 'www.microsoft.com',
      'apple.com', 'www.apple.com', 'amazon.com', 'www.amazon.com',
      'paypal.com', 'www.paypal.com', 'facebook.com', 'www.facebook.com',
      'wikipedia.org', 'www.wikipedia.org', 'youtube.com', 'www.youtube.com',
      'netflix.com', 'www.netflix.com', 'linkedin.com', 'www.linkedin.com',
      'twitter.com', 'x.com', 'openai.com', 'chatgpt.com', 'stackoverflow.com',
      'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'cloudflare.com'
    ];
  }

  /**
   * Calculate Shannon Entropy of a string (measures randomness/obfuscation)
   */
  calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    const len = str.length;
    const frequencies = {};
    for (let i = 0; i < len; i++) {
      const char = str[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    for (const char in frequencies) {
      const p = frequencies[char] / len;
      entropy -= p * Math.log2(p);
    }
    return Number(entropy.toFixed(3));
  }

  /**
   * Extract features from URL for heuristic & machine learning analysis
   */
  extractFeatures(rawUrl) {
    let cleanUrl = rawUrl.trim();
    if (!/^https?:\/\//i.test(cleanUrl)) {
      cleanUrl = 'http://' + cleanUrl;
    }

    let parsed;
    try {
      parsed = new URL(cleanUrl);
    } catch (e) {
      // Fallback manual parser if URL is malformed
      const match = cleanUrl.match(/^([a-z0-9+.-]+):\/\/([^/:]+)(?::(\d+))?(\/.*)?$/i);
      if (match) {
        parsed = {
          protocol: match[1] + ':',
          hostname: match[2],
          port: match[3] || '',
          pathname: match[4] || '/',
          search: '',
          hash: ''
        };
      } else {
        parsed = {
          protocol: 'http:',
          hostname: cleanUrl.replace(/^https?:\/\//i, '').split('/')[0],
          port: '',
          pathname: '/',
          search: '',
          hash: ''
        };
      }
    }

    const hostname = (parsed.hostname || '').toLowerCase();
    const pathname = (parsed.pathname || '').toLowerCase();
    const search = (parsed.search || '').toLowerCase();
    const fullUrl = cleanUrl.toLowerCase();

    // 1. IP Address detection (e.g. http://192.168.1.1/login or hexadecimal/octal IP)
    const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    const ipv6Regex = /^\[?[a-f0-9:]+\]?$/i;
    const hasIpAddress = ipv4Regex.test(hostname) || (hostname.startsWith('[') && ipv6Regex.test(hostname));

    // 2. URL Length
    const urlLength = cleanUrl.length;
    const isLongUrl = urlLength > 75;
    const isVeryLongUrl = urlLength > 110;

    // 3. Dot count in hostname (excessive subdomains)
    const dotCount = (hostname.match(/\./g) || []).length;
    const excessiveDots = dotCount > 3;

    // 4. @ symbol presence (credential trick / redirection)
    const hasAtSymbol = cleanUrl.includes('@');

    // 5. Double slash in path (redirect bypass)
    const hasDoubleSlashInPath = pathname.includes('//');

    // 6. Dash / Hyphen count in hostname
    const hyphenCount = (hostname.match(/-/g) || []).length;
    const excessiveHyphens = hyphenCount >= 2;

    // 7. Presence of port
    const hasNonStandardPort = Boolean(parsed.port && parsed.port !== '80' && parsed.port !== '443');

    // 8. Protocol safety
    const isHttps = parsed.protocol === 'https:';

    // 9. Suspicious keywords count in pathname or query
    const matchedKeywords = [];
    this.suspiciousKeywords.forEach(kw => {
      if (fullUrl.includes(kw)) {
        matchedKeywords.push(kw);
      }
    });

    // 10. High-risk TLD match
    let matchedHighRiskTLD = null;
    for (const tld of this.highRiskTLDs) {
      if (hostname.endsWith(tld)) {
        matchedHighRiskTLD = tld;
        break;
      }
    }

    // 11. Homoglyphs & Punycode (IDN spoofing like xn--...)
    const isPunycode = hostname.includes('xn--');
    const hasNonAscii = /[^\u0000-\u007F]/.test(hostname);

    // 12. Hex / Percent encoding count
    const encodedCount = (cleanUrl.match(/%[0-9a-f]{2}/gi) || []).length;

    // 13. Brand Impersonation / Typosquatting
    let impersonatedBrand = null;
    let isLegitimateBrand = false;

    // Check if it's an exact legitimate domain
    for (const valid of this.whitelistedDomains) {
      if (hostname === valid || hostname.endsWith('.' + valid)) {
        isLegitimateBrand = true;
        break;
      }
    }

    if (!isLegitimateBrand) {
      for (const brand of this.brandTargets) {
        for (const pat of brand.patterns) {
          if (hostname.includes(pat) || pathname.includes(pat)) {
            impersonatedBrand = brand.name;
            break;
          }
        }
        if (impersonatedBrand) break;
      }
    }

    // 14. Subdomain depth
    const parts = hostname.split('.');
    const subdomainCount = Math.max(0, parts.length - 2);

    // 15. Shannon Entropy
    const entropy = this.calculateEntropy(hostname);
    const isHighEntropy = entropy > 3.8;

    return {
      rawUrl: cleanUrl,
      hostname,
      pathname,
      search,
      protocol: parsed.protocol,
      urlLength,
      isLongUrl,
      isVeryLongUrl,
      dotCount,
      excessiveDots,
      hasIpAddress,
      hasAtSymbol,
      hasDoubleSlashInPath,
      hyphenCount,
      excessiveHyphens,
      hasNonStandardPort,
      port: parsed.port || (isHttps ? '443' : '80'),
      isHttps,
      matchedKeywords,
      matchedHighRiskTLD,
      isPunycode,
      hasNonAscii,
      encodedCount,
      impersonatedBrand,
      isLegitimateBrand,
      subdomainCount,
      entropy,
      isHighEntropy
    };
  }

  /**
   * Run Phishing Machine Learning & Heuristic Classification
   */
  analyze(rawUrl) {
    const features = this.extractFeatures(rawUrl);

    // If it's a known whitelisted domain with no malicious path/redirection
    if (features.isLegitimateBrand && !features.hasAtSymbol && !features.hasIpAddress && features.matchedKeywords.length <= 1) {
      return {
        url: features.rawUrl,
        verdict: 'SAFE',
        verdictBengali: 'নিরাপদ (Safe)',
        riskScore: 4,
        confidence: 98,
        statusClass: 'safe',
        summary: 'বিশ্বস্ত এবং বৈধ ডোমেন হিসেবে স্বীকৃত (Verified Legitimate Domain).',
        features,
        featureBreakdown: [
          { name: 'Domain Reputation', score: 0, weight: 30, text: 'Verified Whitelisted Domain' },
          { name: 'Protocol', score: features.isHttps ? 0 : 15, weight: 15, text: features.isHttps ? 'HTTPS Enforced' : 'Unencrypted HTTP' },
          { name: 'URL Structure', score: 0, weight: 20, text: 'Clean, standard structure' },
          { name: 'Entropy', score: 0, weight: 15, text: `Normal lexical entropy (${features.entropy})` },
          { name: 'Brand Safety', score: 0, weight: 20, text: 'Authentic brand infrastructure' }
        ],
        recommendations: [
          'ওয়েবসাইটটি বিশ্বস্ত এবং নিরাপদ বলে নিশ্চিত হওয়া গেছে।',
          'নিয়মিত ব্রাউজ করার জন্য উপযুক্ত।'
        ]
      };
    }

    // Dynamic Heuristic & ML Feature Weights
    let riskPoints = 0;
    const breakdown = [];

    // 1. IP in hostname (+35 points) - Extreme indicator
    if (features.hasIpAddress) {
      riskPoints += 35;
      breakdown.push({
        name: 'IP Hostname',
        penalty: 35,
        type: 'critical',
        detail: 'URL-এ কোনো ডোমেইন নামের পরিবর্তে সরাসরি IP অ্যাড্রেস ব্যবহার করা হয়েছে।'
      });
    }

    // 2. Brand impersonation / typosquatting (+30 points)
    if (features.impersonatedBrand && !features.isLegitimateBrand) {
      riskPoints += 30;
      breakdown.push({
        name: 'Brand Spoofing',
        penalty: 30,
        type: 'critical',
        detail: `${features.impersonatedBrand} ব্র্যান্ডের নাম অসদুপায়ে অনুকরণ করার লক্ষণ পাওয়া গেছে।`
      });
    }

    // 3. @ symbol in URL (+25 points) - Credential phishing trick
    if (features.hasAtSymbol) {
      riskPoints += 25;
      breakdown.push({
        name: '@ Redirection Trick',
        penalty: 25,
        type: 'critical',
        detail: '@ চিহ্ন ব্যবহার করে ব্যবহারকারীর চোখ ফাঁকি দিয়ে ক্ষতিকারক লিংকে রিডাইরেক্ট করা হচ্ছে।'
      });
    }

    // 4. High-risk TLD (+20 points)
    if (features.matchedHighRiskTLD) {
      riskPoints += 20;
      breakdown.push({
        name: 'High-Risk TLD',
        penalty: 20,
        type: 'high',
        detail: `ঝুঁকিপূর্ণ TLD (${features.matchedHighRiskTLD}) শনাক্ত হয়েছে, যা ফিশিং স্ক্যামে বহুল ব্যবহৃত।`
      });
    }

    // 5. Insecure HTTP (+15 points)
    if (!features.isHttps) {
      riskPoints += 15;
      breakdown.push({
        name: 'Insecure HTTP',
        penalty: 15,
        type: 'medium',
        detail: 'কোনো SSL/TLS এনক্রিপশন নেই (Plain HTTP)। লগইন তথ্য চুরি হতে পারে।'
      });
    }

    // 6. Suspicious Keywords (+8 points each, capped at 24)
    if (features.matchedKeywords.length > 0) {
      const kwPenalty = Math.min(24, features.matchedKeywords.length * 8);
      riskPoints += kwPenalty;
      breakdown.push({
        name: 'Phishing Keywords',
        penalty: kwPenalty,
        type: 'high',
        detail: `সন্দেহজনক কীওয়ার্ড পাওয়া গেছে: ${features.matchedKeywords.slice(0, 4).join(', ')}`
      });
    }

    // 7. Punycode / Homoglyph / Non-ASCII (+20 points)
    if (features.isPunycode || features.hasNonAscii) {
      riskPoints += 20;
      breakdown.push({
        name: 'Homoglyph / Punycode',
        penalty: 20,
        type: 'critical',
        detail: 'Punycode বা ছদ্মবেশী অক্ষর ব্যবহার করে আসল সাইট নকল করার চেষ্টা করা হয়েছে।'
      });
    }

    // 8. Excessive subdomains / deep nesting (+15 points)
    if (features.subdomainCount >= 3 || features.excessiveDots) {
      riskPoints += 15;
      breakdown.push({
        name: 'Subdomain Cloaking',
        penalty: 15,
        type: 'medium',
        detail: 'অতিরিক্ত সাবডোমেন দিয়ে আসল ডোমেনকে আড়াল করার চেষ্টা করা হয়েছে।'
      });
    }

    // 9. Excessive Hyphens in domain (+12 points)
    if (features.excessiveHyphens) {
      riskPoints += 12;
      breakdown.push({
        name: 'Hyphen Abuse',
        penalty: 12,
        type: 'low',
        detail: `ডোমেনটিতে অস্বাভাবিক সংখ্যক হাইফেন (${features.hyphenCount}) রয়েছে।`
      });
    }

    // 10. Long & Obfuscated URL (+10 points)
    if (features.isVeryLongUrl) {
      riskPoints += 10;
      breakdown.push({
        name: 'Obfuscated Length',
        penalty: 10,
        type: 'low',
        detail: `অস্বাভাবিক বড় URL (${features.urlLength} অক্ষর)। তথ্য গোপনের সম্ভাবনা।`
      });
    }

    // 11. High lexical entropy (+12 points)
    if (features.isHighEntropy) {
      riskPoints += 12;
      breakdown.push({
        name: 'High Randomness (Entropy)',
        penalty: 12,
        type: 'medium',
        detail: `উচ্চ এনট্রপি রেটিং (${features.entropy}), ডোমেনটি এলগরিদমে তৈরি বা এনকোড করা।`
      });
    }

    // 12. Non-standard port (+10 points)
    if (features.hasNonStandardPort) {
      riskPoints += 10;
      breakdown.push({
        name: 'Suspicious Port',
        penalty: 10,
        type: 'medium',
        detail: `অস্বাভাবিক পোর্ট (${features.port}) ব্যবহার করা হয়েছে।`
      });
    }

    // Normalize final score between 0 and 100
    const finalScore = Math.min(100, Math.max(5, riskPoints));

    // Determine Verdict
    let verdict = 'SAFE';
    let verdictBengali = 'নিরাপদ (Safe)';
    let statusClass = 'safe';
    let summary = 'কোনো উল্লেখযোগ্য ফিশিং বা ক্ষতিকারক লক্ষ্মণ ধরা পড়েনি।';

    if (finalScore >= 70) {
      verdict = 'PHISHING / MALICIOUS';
      verdictBengali = 'মারাত্মক ঝুঁকিপূর্ণ (Phishing / Dangerous)';
      statusClass = 'danger';
      summary = 'উচ্চ সতর্কবার্তা! এটি একটি নিশ্চিত বা অত্যন্ত সম্ভাব্য ফিশিং ওয়েবসাইট। এখানে পাসওয়ার্ড বা ব্যক্তিগত তথ্য দেবেন না।';
    } else if (finalScore >= 45) {
      verdict = 'SUSPICIOUS';
      verdictBengali = 'সন্দেহজনক (Suspicious)';
      statusClass = 'warning';
      summary = 'সাইটটিতে বেশ কিছু বিপজ্জনক অসঙ্গতি রয়েছে। সতর্কতার সাথে ভিজিট করুন।';
    } else if (finalScore >= 25) {
      verdict = 'LOW RISK';
      verdictBengali = 'স্বল্প ঝুঁকি (Low Risk)';
      statusClass = 'caution';
      summary = 'সাইটে কিছু অস্বাভাবিকতা পাওয়া গেছে তবে ফিশিংয়ের সুস্পষ্ট প্রমাণ নেই।';
    }

    // Actionable recommendations based on findings
    const recommendations = [];
    if (finalScore >= 70) {
      recommendations.push('🚨 এই লিংকে কোনো ব্যক্তিগত তথ্য, ইউজারনেম বা পাসওয়ার্ড প্রবেশ করাবেন না।');
      recommendations.push('🛡️ অবিলম্বে পেজটি বন্ধ করে দিন এবং ব্রাউজার হিস্টোরি ও ক্যাশ ক্লিয়ার করুন।');
      recommendations.push('📢 এই URL টি আমাদের Collaborative Intelligence প্ল্যাটফর্মে রিপোর্ট করুন।');
    } else if (finalScore >= 45) {
      recommendations.push('⚠️ URL-এর ডোমেইন বানান এবং অ্যাড্রেস বার ভালো করে পরীক্ষা করুন।');
      recommendations.push('🔒 SSL সার্টিফিকেট এবং প্যাডলক আইকন ভ্যালিডেশন চেক করুন।');
      recommendations.push('🚫 সন্দেহজনক কোনো ফাইল বা এক্সটেনশন ডাউনলোড করা থেকে বিরত থাকুন।');
    } else {
      recommendations.push('✅ সাধারণ সতর্কতা বজায় রাখুন এবং টু-ফ্যাক্টর অথেন্টিকেশন (2FA) সক্রিয় রাখুন।');
    }

    return {
      url: features.rawUrl,
      verdict,
      verdictBengali,
      riskScore: finalScore,
      confidence: Math.min(99, Math.max(75, 60 + breakdown.length * 8)),
      statusClass,
      summary,
      features,
      breakdown,
      recommendations
    };
  }
}

// Export singleton instance
window.phishingDetector = new PhishingDetector();
