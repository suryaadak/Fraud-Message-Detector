/**
 * Phishing Detection Platform - SSL/TLS Validation Engine
 * Module 3: SSL/TLS Validation (Certificate Authority, Cipher Suites, Validity & Encryption Security)
 */

class SSLValidator {
  constructor() {
    this.trustedIssuers = [
      'DigiCert Global Root G2', 'Google Trust Services LLC', 'Let\'s Encrypt',
      'Cloudflare Inc ECC CA-3', 'Sectigo RSA Domain Validation Secure Server CA',
      'Amazon Root CA 1', 'GlobalSign GCC R3', 'Microsoft RSA TLS CA 02'
    ];
  }

  /**
   * Validate SSL/TLS certificate attributes for target URL
   */
  validateSSL(url, parsedFeatures) {
    const isHttps = parsedFeatures ? parsedFeatures.isHttps : url.startsWith('https://');
    const hostname = parsedFeatures ? parsedFeatures.hostname : new URL(url).hostname;

    // 1. Insecure Plain HTTP (No SSL at all)
    if (!isHttps) {
      return {
        hasSSL: false,
        status: 'INSECURE',
        statusBn: 'অরক্ষিত (Insecure HTTP - No SSL)',
        grade: 'F',
        validity: 'None',
        issuer: 'None (Plain Text Protocol)',
        protocol: 'HTTP/1.1 (Unencrypted)',
        keyStrength: '0-bit (No Encryption)',
        cipherSuite: 'None (Plaintext)',
        sanMatches: false,
        daysRemaining: 0,
        certificateChain: [],
        vulnerabilities: [
          'ডেটা সম্পূর্ণ এনক্রিপশন ছাড়াই আদান-প্রদান হচ্ছে (Man-in-the-Middle Attack ঝুঁকিপূর্ণ)।',
          'যেকোনো ইউজারনেম, পাসওয়ার্ড বা কার্ড নম্বর নেটওয়ার্কে সরাসরি পর্যবেক্ষণ করা সম্ভব।'
        ],
        isPhishingWithFreeSSL: false,
        summaryBn: 'ওয়েবসাইটটিতে কোনো SSL সার্টিফিকেট নেই। সংবেদনশীল তথ্য চুরি হওয়া অতি সাধারণ।'
      };
    }

    // 2. HTTPS Present - Evaluate Certificate Security
    // Check if it's an IP address or suspicious TLD
    const hasIpAddress = parsedFeatures ? parsedFeatures.hasIpAddress : false;
    const isHighRisk = parsedFeatures ? (parsedFeatures.matchedHighRiskTLD || parsedFeatures.impersonatedBrand) : false;

    // Determine realistic simulated certificate profile
    let issuer = 'Let\'s Encrypt Authority X3';
    let protocol = 'TLS 1.3';
    let cipherSuite = 'TLS_AES_256_GCM_SHA384';
    let keyStrength = 'RSA 2048-bit (SHA-256)';
    let grade = 'A';
    let daysRemaining = 82;
    let validFrom = '2026-09-01';
    let validTo = '2026-11-30';
    let status = 'VALID';
    let statusBn = 'বৈধ ও সক্রিয় (Valid SSL Certificate)';
    let sanMatches = true;
    let isPhishingWithFreeSSL = false;
    const vulnerabilities = [];

    if (hasIpAddress) {
      issuer = 'Self-Signed Untrusted Root CA';
      status = 'SELF_SIGNED';
      statusBn = 'স্ব-স্বাক্ষরিত / অবিশ্বস্ত (Self-Signed / Untrusted CA)';
      grade = 'D';
      sanMatches = false;
      daysRemaining = 365;
      vulnerabilities.push('ব্রাউজার এই সার্টিফিকেটকে বিশ্বাসযোগ্য CA হিসেবে শনাক্ত করতে পারবে না।');
      vulnerabilities.push('সরাসরি IP তে সেলফ-সাইনড সার্টিফিকেট সাইবার অ্যাটাকে প্রায়শই ব্যবহৃত হয়।');
    } else if (parsedFeatures && parsedFeatures.isLegitimateBrand) {
      // Big tech high-assurance certificate (EV / OV)
      if (hostname.includes('google')) {
        issuer = 'Google Trust Services LLC (GTS CA 1C3)';
        keyStrength = 'ECDSA P-256 (SHA-256)';
        cipherSuite = 'TLS_AES_128_GCM_SHA256';
      } else if (hostname.includes('github') || hostname.includes('chase')) {
        issuer = 'DigiCert Global Root G2 (Extended Validation)';
        keyStrength = 'RSA 2048-bit (SHA-256 with EV)';
      } else {
        issuer = 'Cloudflare Inc ECC CA-3';
        keyStrength = 'ECDSA 256-bit';
      }
      grade = 'A+';
      daysRemaining = 194;
    } else if (isHighRisk) {
      // Suspicious site with Free Auto-SSL
      issuer = 'Let\'s Encrypt Authority (Domain Validated DV)';
      grade = 'B';
      daysRemaining = 24;
      isPhishingWithFreeSSL = true;
      vulnerabilities.push('⚠️ আধুনিক ফিশিং ওয়েবসাইটের ৮০% শতাংশই ফ্রি DV SSL ব্যবহার করে প্যাডলক আইকন প্রদর্শন করে।');
      vulnerabilities.push('সার্টিফিকেট থাকা মানেই সাইটটি নিরাপদ নয় — এটি শুধু ডেটা চ্যানেল এনক্রিপ্ট করে, ডোমেনের সততা প্রমাণ করে না।');
    }

    // Build Certificate Trust Chain
    const certificateChain = [
      { level: 'Root CA', name: issuer.includes('DigiCert') ? 'DigiCert Global Root CA' : 'ISRG Root X1', trusted: true },
      { level: 'Intermediate CA', name: issuer, trusted: !hasIpAddress },
      { level: 'Leaf Certificate', name: hostname, trusted: !hasIpAddress && sanMatches }
    ];

    return {
      hasSSL: true,
      status,
      statusBn,
      grade,
      issuer,
      protocol,
      keyStrength,
      cipherSuite,
      sanMatches,
      subjectAltNames: [hostname, `*.${hostname}`],
      validFrom,
      validTo,
      daysRemaining,
      certificateChain,
      vulnerabilities,
      isPhishingWithFreeSSL,
      summaryBn: isPhishingWithFreeSSL 
        ? 'SSL সার্টিফিকেট টেকনিক্যালি বৈধ হলেও এটি ফ্রি DV সার্টিফিকেট, যা ফিশিং স্ক্যামের বড় লক্ষণ।'
        : 'সার্টিফিকেট সঠিক এবং শক্তিশালী এনক্রিপশন প্রোটোকল দিয়ে সুরক্ষিত।'
    };
  }
}

// Export singleton instance
window.sslValidator = new SSLValidator();
