/**
 * Phishing Detection Platform - Web Security Assessment Engine
 * Module 4: Web Security Assessment (HTTP Security Headers, Configuration Audit & Vulnerability Scoring)
 */

class WebSecurityAssessor {
  constructor() {
    this.standardHeaders = [
      {
        name: 'Strict-Transport-Security (HSTS)',
        key: 'strict-transport-security',
        weight: 25,
        desc: 'ব্রাউজারকে সর্বদা এনক্রিপ্ট করা HTTPS কানেকশন ব্যবহারে বাধ্য করে।',
        goodValue: 'max-age=31536000; includeSubDomains; preload'
      },
      {
        name: 'Content-Security-Policy (CSP)',
        key: 'content-security-policy',
        weight: 30,
        desc: 'Cross-Site Scripting (XSS) এবং ক্ষতিকর স্ক্রিপ্ট ইনজেকশন প্রতিরোধ করে।',
        goodValue: "default-src 'self'; script-src 'self' cdn.example.com"
      },
      {
        name: 'X-Frame-Options',
        key: 'x-frame-options',
        weight: 15,
        desc: 'ক্লিকজ্যাকিং (Clickjacking) এবং অননুমোদিত iframe এম্বিডিং প্রতিরোধ করে।',
        goodValue: 'DENY বা SAMEORIGIN'
      },
      {
        name: 'X-Content-Type-Options',
        key: 'x-content-type-options',
        weight: 10,
        desc: 'MIME-টাইপ বিভ্রান্তি বা ব্রাউজার দ্বারা ভুল স্ক্রিপ্ট এক্সিকিউট হওয়া ঠেকায়।',
        goodValue: 'nosniff'
      },
      {
        name: 'Referrer-Policy',
        key: 'referrer-policy',
        weight: 10,
        desc: 'অন্য সাইটে যাওয়ার সময় সংবেদনশীল URL প্যারামিটার ফাঁস হওয়া রোধ করে।',
        goodValue: 'strict-origin-when-cross-origin'
      },
      {
        name: 'Permissions-Policy',
        key: 'permissions-policy',
        weight: 10,
        desc: 'ক্যামেরা, মাইক্রোফোন বা লোকেশন অ্যাক্সেস অননুমোদিতভাবে নেওয়া নিয়ন্ত্রণ করে।',
        goodValue: 'camera=(), microphone=(), geolocation=()'
      }
    ];
  }

  /**
   * Run security assessment on website configuration
   */
  assessSecurity(url, parsedFeatures) {
    const isHttps = parsedFeatures ? parsedFeatures.isHttps : url.startsWith('https://');
    const isLegit = parsedFeatures ? parsedFeatures.isLegitimateBrand : false;
    const isSuspicious = parsedFeatures ? (parsedFeatures.hasIpAddress || parsedFeatures.impersonatedBrand || parsedFeatures.matchedHighRiskTLD) : false;

    // Evaluate Header Presence based on domain archetype
    const evaluatedHeaders = this.standardHeaders.map(header => {
      let isPresent = false;
      let status = 'Missing';
      let statusBn = 'অনুপস্থিত (Missing)';
      let statusClass = 'danger';
      let value = 'Not configured';

      if (isLegit) {
        // High-security authoritative site
        isPresent = true;
        status = 'Secured';
        statusBn = 'নিরাপদ (Active)';
        statusClass = 'safe';
        value = header.goodValue;
      } else if (!isSuspicious && isHttps) {
        // Average commercial site: has some headers, misses others
        if (['strict-transport-security', 'x-content-type-options', 'x-frame-options'].includes(header.key)) {
          isPresent = true;
          status = 'Configured';
          statusBn = 'সক্রিয় (Configured)';
          statusClass = 'safe';
          value = header.goodValue;
        } else {
          isPresent = false;
          status = 'Missing';
          statusBn = 'অনুপস্থিত (Missing)';
          statusClass = 'warning';
          value = 'Not present in response headers';
        }
      } else {
        // Phishing / Malicious site: almost zero security headers
        isPresent = false;
        status = 'Missing';
        statusBn = 'অনুপস্থিত (Missing)';
        statusClass = 'danger';
        value = 'Header missing completely';
      }

      return {
        ...header,
        isPresent,
        status,
        statusBn,
        statusClass,
        value
      };
    });

    // Calculate Security Score (0 to 100)
    let totalScore = 0;
    evaluatedHeaders.forEach(h => {
      if (h.isPresent) totalScore += h.weight;
    });

    if (!isHttps) {
      totalScore = 0; // Without HTTPS, HTTP headers are meaningless
    }

    // Determine Letter Grade
    let grade = 'F';
    let gradeColor = 'text-red-500';
    let gradeSummary = 'চরম নিরাপত্তাহীনতা';

    if (totalScore >= 90) {
      grade = 'A+';
      gradeColor = 'text-emerald-400';
      gradeSummary = 'অত্যন্ত সুসংগঠিত ও আধুনিক নিরাপত্তা কনফিগারেশন';
    } else if (totalScore >= 75) {
      grade = 'A';
      gradeColor = 'text-green-400';
      gradeSummary = 'শক্তিশালী সুরক্ষা পলিসি সক্রিয়';
    } else if (totalScore >= 55) {
      grade = 'B';
      gradeColor = 'text-yellow-400';
      gradeSummary = 'মাঝারি নিরাপত্তা, বেশ কিছু সুপারিশ বাস্তবায়িত নয়';
    } else if (totalScore >= 35) {
      grade = 'C';
      gradeColor = 'text-orange-400';
      gradeSummary = 'দুর্বল কনফিগারেশন, আক্রমণকারীদের পক্ষে ঝুঁকিপূর্ণ';
    } else {
      grade = 'F';
      gradeColor = 'text-red-500';
      gradeSummary = 'গুরুত্বপূর্ণ কোনো নিরাপত্তা হেডার নেই';
    }

    // Additional Web Security Vectors
    const additionalChecks = [
      {
        title: 'Cookie Security Flags',
        titleBn: 'কুকি সুরক্ষা ফ্ল্যাগ (Secure / HttpOnly / SameSite)',
        passed: isLegit || (!isSuspicious && isHttps),
        detail: isLegit ? 'Secure এবং SameSite ফ্ল্যাগ যথাযথভাবে সক্রিয়।' : 'কুকিতে সেশন হাইজ্যাকিংয়ের বিরুদ্ধে ফ্ল্যাগ অনুপস্থিত থাকতে পারে।'
      },
      {
        title: 'Mixed Content Protection',
        titleBn: 'মিক্সড কনটেন্ট প্রোটেকশন (Mixed Content)',
        passed: isHttps,
        detail: isHttps ? 'কোনো অনিরাপদ HTTP রিসোর্স লোড হচ্ছে না।' : 'সাইটটি সম্পূর্ণ অসুরক্ষিত।'
      },
      {
        title: 'Server Information Disclosure',
        titleBn: 'সার্ভার ইনফরমেশন ডিসক্লোজার (Server Banners)',
        passed: isLegit,
        detail: isLegit ? 'সার্ভার সংস্করণ তথ্য লুকানো হয়েছে।' : 'সার্ভার ও ফ্রেমওয়ার্ক ভার্সন দৃশ্যমান হতে পারে।'
      },
      {
        title: 'Clickjacking Resistance',
        titleBn: 'ক্লিকজ্যাকিং প্রতিরোধ সক্ষমতা',
        passed: isLegit || (!isSuspicious && isHttps),
        detail: isLegit ? 'X-Frame-Options ও frame-ancestors ডিরেক্টিভ সক্রিয়।' : 'অননুমোদিত আইফ্রেমে সাইটটি লোড হওয়ার ঝুঁকি রয়েছে।'
      }
    ];

    return {
      totalScore,
      grade,
      gradeColor,
      gradeSummary,
      headers: evaluatedHeaders,
      additionalChecks,
      headersPassedCount: evaluatedHeaders.filter(h => h.isPresent).length,
      headersTotalCount: evaluatedHeaders.length
    };
  }
}

// Export singleton instance
window.webSecurityAssessor = new WebSecurityAssessor();
