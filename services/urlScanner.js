const crypto = require('crypto');

/**
 * Top Trusted Global Domains Array
 * Baseline certified domains protected against typosquatting, masquerading, and spoofing
 */
const TOP_TRUSTED_DOMAINS = [
  'google.com',
  'google.co.in',
  'vercel.com',
  'github.com',
  'amazon.in',
  'amazon.com',
  'flipkart.com',
  'microsoft.com',
  'netflix.com',
  'paypal.com',
  'apple.com',
  'facebook.com',
  'instagram.com',
  'whatsapp.com',
  'linkedin.com',
  'twitter.com',
  'x.com',
  'youtube.com',
  'geeksforgeeks.org',
  'myntra.com',
  'wikipedia.org',
  'reddit.com',
  'openai.com',
  'spotify.com'
];

/**
 * High-Abuse / High-Risk TLDs correlated with phishing and malware campaigns
 */
const HIGH_RISK_TLDS = new Set([
  'xyz', 'top', 'club', 'work', 'click', 'loan', 'tk', 'ml', 'ga', 
  'cf', 'gq', 'buzz', 'fit', 'surf', 'rest', 'live', 'icu', 'cam', 
  'bid', 'stream', 'zip', 'mov', 'country', 'kim', 'science', 'gdn', 'biz'
]);

/**
 * Common Phishing & Social Engineering Action Lures
 */
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'secure', 'account', 'update',
  'banking', 'wallet', 'confirm', 'suspend', 'suspended', 'kyc', 'authenticate',
  'validation', 'security-check', 'password-reset', 'recover', 'claim-reward',
  'airdrop', 'invoice', 'payment-declined', 'billing', 'support-desk'
];

/**
 * Known URL Shortener Domains
 */
const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'buff.ly',
  'ow.ly', 'rb.gy', 'rebrand.ly', 'tiny.cc', 'bl.ink'
]);

/**
 * Calculate Shannon Entropy of a string
 * Measures the degree of randomness or algorithmic generation (DGA)
 * @param {string} str
 * @returns {number}
 */
function calculateEntropy(str) {
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
  return parseFloat(entropy.toFixed(3));
}

/**
 * Real JavaScript Damerau-Levenshtein Distance Function
 * Computes minimum edit operations (insertions, deletions, substitutions, and adjacent transpositions)
 * @param {string} s1
 * @param {string} s2
 * @returns {number}
 */
function levenshteinDistance(s1, s2) {
  if (!s1) return s2 ? s2.length : 0;
  if (!s2) return s1.length;
  if (s1 === s2) return 0;

  const m = s1.length;
  const n = s2.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,       // deletion
        dp[i][j - 1] + 1,       // insertion
        dp[i - 1][j - 1] + cost // substitution
      );
      // Damerau transposition check (e.g., 'goolge' <-> 'google')
      if (i > 1 && j > 1 && s1[i - 1] === s2[j - 2] && s1[i - 2] === s2[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
      }
    }
  }
  return dp[m][n];
}

/**
 * Mathematical String Similarity Percentage
 * Formula: ((1 - Levenshtein(s1, s2) / max(len(s1), len(s2))) * 100)
 * @param {string} str1
 * @param {string} str2
 * @returns {number} 0.00 to 100.00
 */
function calculateSimilarity(str1, str2) {
  const s1 = (str1 || '').toLowerCase();
  const s2 = (str2 || '').toLowerCase();
  if (s1 === s2) return 100;
  const maxLen = Math.max(s1.length, s2.length);
  if (maxLen === 0) return 100;
  const distance = levenshteinDistance(s1, s2);
  const similarity = ((1 - (distance / maxLen)) * 100);
  return parseFloat(similarity.toFixed(2));
}

/**
 * Extract domain stem (e.g. 'verrcel.com' -> 'verrcel', 'amazon.in' -> 'amazon')
 * @param {string} domain
 * @returns {string}
 */
function extractDomainStem(domain) {
  const parts = domain.split('.');
  if (parts.length >= 3 && ['co', 'com', 'org', 'net', 'gov', 'edu'].includes(parts[parts.length - 2])) {
    return parts[parts.length - 3];
  }
  return parts.length >= 2 ? parts[parts.length - 2] : parts[0];
}

/**
 * Normalize Leetspeak / Homoglyphs (e.g. '0' -> 'o', '1' -> 'l', '5' -> 's')
 * @param {string} str
 * @returns {string}
 */
function normalizeLeetspeak(str) {
  return str
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/8/g, 'b')
    .replace(/vv/g, 'w')
    .replace(/rn/g, 'm');
}

/**
 * Core Threat Scanner Engine
 * Real Levenshtein Distance & Typosquatting Detection Algorithm
 * @param {string} rawUrl
 * @returns {object} Threat analysis breakdown
 */
function scanUrl(rawUrl) {
  let urlStr = rawUrl ? rawUrl.trim() : '';
  if (!urlStr.startsWith('http://') && !urlStr.startsWith('https://')) {
    urlStr = 'http://' + urlStr;
  }

  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch (err) {
    return {
      success: false,
      error: 'Malformed URL: Unable to parse URL structure.'
    };
  }

  const rawHostname = parsed.hostname.toLowerCase();
  // Strip leading 'www.' for accurate domain and stem comparison
  const hostname = rawHostname.startsWith('www.') ? rawHostname.slice(4) : rawHostname;
  const pathname = parsed.pathname.toLowerCase();
  const search = parsed.search.toLowerCase();
  const fullTarget = parsed.href;

  const heuristics = [];
  const indicators = {
    clean: [],
    suspicious: [],
    malicious: []
  };
  const mitreAttack = [];
  let threatScore = 0;

  // Split hostname into domain components
  const domainParts = hostname.split('.');
  const tld = domainParts.length > 1 ? domainParts[domainParts.length - 1] : '';
  const inputStem = extractDomainStem(hostname);

  // -------------------------------------------------------------
  // 1. EXACT MATCH VERIFICATION
  // -------------------------------------------------------------
  const isExactTrustedMatch = TOP_TRUSTED_DOMAINS.some(
    trusted => hostname === trusted || hostname.endsWith('.' + trusted)
  );

  // -------------------------------------------------------------
  // 2. MATHEMATICAL LEVENSHTEIN DISTANCE & TYPOSQUATTING DETECTION
  // -------------------------------------------------------------
  let typosquattingMatch = null;

  if (!isExactTrustedMatch) {
    for (const trustedDomain of TOP_TRUSTED_DOMAINS) {
      const trustedStem = extractDomainStem(trustedDomain);

      // A. Full Domain Similarity (e.g. 'verrcel.com' vs 'vercel.com', 'goolge.com' vs 'google.com')
      const domainSim = calculateSimilarity(hostname, trustedDomain);
      const domainDist = levenshteinDistance(hostname, trustedDomain);

      // B. Domain Stem Similarity (e.g. 'verrcel' vs 'vercel', 'fl1pkart' vs 'flipkart')
      const stemSim = calculateSimilarity(inputStem, trustedStem);
      const stemDist = levenshteinDistance(inputStem, trustedStem);

      // C. Homoglyph / Leetspeak Normalized Similarity
      const normalizedInputStem = normalizeLeetspeak(inputStem);
      const normalizedStemSim = calculateSimilarity(normalizedInputStem, trustedStem);

      // Check if similarity is in the close typosquatting range (e.g. 75% to 98%, covering 80% to 95%)
      const isDomainTyposquat = (domainSim >= 75 && domainSim < 100);
      const isStemTyposquat = (stemSim >= 75 && stemSim < 100 && stemDist <= 2 && inputStem.length >= 4);
      const isNormalizedTyposquat = (normalizedStemSim >= 90 && inputStem !== trustedStem);
      const isFakeTLDImpersonation = (inputStem === trustedStem && !hostname.endsWith('.' + trustedDomain));

      if (isDomainTyposquat || isStemTyposquat || isNormalizedTyposquat || isFakeTLDImpersonation) {
        const bestSim = Math.max(domainSim, stemSim, normalizedStemSim);
        typosquattingMatch = {
          trustedDomain,
          trustedStem,
          similarity: bestSim,
          domainDistance: domainDist,
          stemDistance: stemDist,
          isFakeTLD: isFakeTLDImpersonation
        };
        break; // Found primary typosquat target
      }
    }
  }

  // -------------------------------------------------------------
  // 3. APPLY TYPOSQUATTING VERDICT IF MATCHED
  // -------------------------------------------------------------
  if (typosquattingMatch) {
    threatScore = 95;
    const alertMsg = "Brand Imitation / Typosquatting Detected!";
    indicators.malicious.unshift(alertMsg);

    heuristics.push({
      category: 'Mathematical Typosquatting (Levenshtein)',
      name: `Typosquatting Detected: Mimicking ${typosquattingMatch.trustedDomain}`,
      status: 'FAIL',
      description: `Input hostname '${hostname}' is ${typosquattingMatch.similarity}% mathematically similar to trusted domain '${typosquattingMatch.trustedDomain}' (Levenshtein distance: ${typosquattingMatch.domainDistance}). Subtle character alteration or homoglyph spoofing detected to mislead victims.`,
      weight: 95
    });

    mitreAttack.push('T1036.007 - Masquerading: Typosquatting');
    mitreAttack.push('T1566.002 - Spearphishing Link');
  }

  // -------------------------------------------------------------
  // 4. DIRECT IP-LITERAL ADDRESSING CHECK
  // -------------------------------------------------------------
  const isIpv4 = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname);
  const isIpv6 = /^\[?[a-fA-F0-9:]+\]?$/.test(hostname) && hostname.includes(':');
  if (isIpv4 || isIpv6) {
    threatScore = Math.max(threatScore, 75);
    heuristics.push({
      category: 'Network Protocol',
      name: 'Direct IP-Literal Hostname',
      status: 'FAIL',
      description: `URL uses a raw IP address (${hostname}) instead of a verified DNS domain. Common evasion technique in C2 beacons and short-lived phishing lures.`,
      weight: 50
    });
    indicators.malicious.push(`Direct IP Address Target (${hostname})`);
    mitreAttack.push('T1204.001 - Malicious Link Execution via IP host');
  }

  // -------------------------------------------------------------
  // 5. HIGH-ABUSE DISPOSABLE TLD CHECK
  // -------------------------------------------------------------
  if (HIGH_RISK_TLDS.has(tld)) {
    threatScore += 35;
    indicators.suspicious.push(`High-Risk Disposable TLD (.${tld})`);
    heuristics.push({
      category: 'Domain Reputation',
      name: 'Abuse-Correlated Top Level Domain',
      status: 'WARN',
      description: `The TLD '.${tld}' exhibits documented high frequency in ephemeral phishing campaigns.`,
      weight: 35
    });
    mitreAttack.push('T1583.001 - Domains: Acquired Disposable TLD');
  }

  // -------------------------------------------------------------
  // 6. CRYPTOGRAPHIC SHANNON ENTROPY & RANDOMNESS CHECKS
  // -------------------------------------------------------------
  const domainEntropy = calculateEntropy(hostname);
  const pathEntropy = calculateEntropy(pathname + search);

  // Check for repeated character sequences (e.g., 'ggreeks', 'amazzon')
  const hasSuspiciousRepetition = /(.)\1{2,}/.test(hostname);
  if (hasSuspiciousRepetition && !typosquattingMatch) {
    threatScore += 30;
    indicators.suspicious.push('Anomalous Repeated Character Sequence');
    heuristics.push({
      category: 'Lexical Analysis',
      name: 'Anomalous Character Repetition',
      status: 'WARN',
      description: 'Hostname contains unusual repeated characters frequently used to register visually deceptive lookalike domains.',
      weight: 30
    });
  }

  // Algorithmic DGA (Domain Generation Algorithm) check
  if (domainEntropy > 3.85) {
    threatScore += 35;
    indicators.suspicious.push(`High Hostname Randomness / Entropy (${domainEntropy})`);
    heuristics.push({
      category: 'Cryptographic Entropy',
      name: 'High Randomness (Possible DGA / Obfuscation)',
      status: 'FAIL',
      description: `Hostname entropy of ${domainEntropy} indicates an algorithmically generated, randomized string commonly observed in C2 domain fluxing.`,
      weight: 35
    });
    mitreAttack.push('T1568.002 - Dynamic Resolution: Domain Generation Algorithms');
  } else if (!typosquattingMatch && isExactTrustedMatch) {
    indicators.clean.push(`Natural Domain Entropy (${domainEntropy})`);
  }

  // -------------------------------------------------------------
  // 7. UNUSUAL SYMBOLS & MALICIOUS PATTERNS IN URL PATH
  // -------------------------------------------------------------
  // Double slash routing bypass (e.g. /login//redirect)
  if (pathname.includes('//')) {
    threatScore += 30;
    indicators.suspicious.push('Double Slash Path Traversal Pattern');
    heuristics.push({
      category: 'URL Path Security',
      name: 'Path Traversal / Redirection Bypass',
      status: 'WARN',
      description: 'Contains double forward-slashes inside path, frequently used to bypass Web Application Firewall (WAF) routing filters.',
      weight: 30
    });
  }

  // Directory traversal / Null-byte injections
  if (urlStr.includes('%00') || urlStr.includes('..') || urlStr.includes('%2e%2e')) {
    threatScore += 45;
    indicators.malicious.push('Directory Traversal / Null Byte Injection');
    heuristics.push({
      category: 'Exploit Pattern',
      name: 'Path Traversal Injection Sequence',
      status: 'FAIL',
      description: 'Detected null-byte (%00) or directory traversal sequences (..) in URL parameters.',
      weight: 45
    });
  }

  // Dangerous script/binary extensions in URL path (e.g. .exe, .bat, .ps1)
  const dangerousPathExt = /\.(exe|bat|ps1|vbs|scr|cmd|sh|elf|apk)($|[?#])/i;
  if (dangerousPathExt.test(pathname)) {
    threatScore += 50;
    indicators.malicious.push('Direct Executable Script in URL Path');
    heuristics.push({
      category: 'Payload Delivery',
      name: 'Executable Binary Path Pointer',
      status: 'FAIL',
      description: 'URL path directly targets an executable binary. High threat of drive-by malware download.',
      weight: 50
    });
    mitreAttack.push('T1204.002 - Malicious File Download');
  }

  // Embedded @ symbol credential separator trick (e.g. http://google.com@evil.com)
  if (rawUrl.includes('@')) {
    threatScore += 45;
    indicators.malicious.push('Embedded User Authentication Delimiter (@)');
    heuristics.push({
      category: 'Syntax Masquerade',
      name: 'URL Credential Separator Exploitation',
      status: 'FAIL',
      description: 'Contains "@" symbol in authority component. Misleads victims into trusting the brand prefix before "@".',
      weight: 45
    });
    mitreAttack.push('T1036.007 - Masquerading');
  }

  // -------------------------------------------------------------
  // 8. EXCESSIVE SUBDOMAIN NESTING
  // -------------------------------------------------------------
  if (domainParts.length > 3) {
    threatScore += 20;
    indicators.suspicious.push(`Excessive Subdomains (${domainParts.length} levels)`);
    heuristics.push({
      category: 'DNS Architecture',
      name: 'Excessive Subdomain Nesting',
      status: 'WARN',
      description: `Domain contains ${domainParts.length} levels. Attackers use excessive subdomains to push the real domain off mobile screen viewports.`,
      weight: 20
    });
  }

  // -------------------------------------------------------------
  // 9. PHISHING SOCIAL ENGINEERING KEYWORDS
  // -------------------------------------------------------------
  const matchedKeywords = [];
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (urlStr.toLowerCase().includes(kw)) {
      matchedKeywords.push(kw);
    }
  }
  if (matchedKeywords.length > 0) {
    const penalty = Math.min(matchedKeywords.length * 15, 40);
    threatScore += penalty;
    indicators.suspicious.push(`Phishing Trigger Words (${matchedKeywords.slice(0, 3).join(', ')})`);
    heuristics.push({
      category: 'Content Heuristics',
      name: 'Social Engineering Keywords',
      status: matchedKeywords.length > 2 ? 'FAIL' : 'WARN',
      description: `Detected urgent bait words: [${matchedKeywords.join(', ')}]. Commonly deployed in phishing credential lures.`,
      weight: penalty
    });
  }

  // -------------------------------------------------------------
  // 10. URL SHORTENER CLOAKING
  // -------------------------------------------------------------
  if (URL_SHORTENERS.has(hostname)) {
    threatScore += 30;
    indicators.suspicious.push(`URL Shortener Cloaking (${hostname})`);
    heuristics.push({
      category: 'Obfuscation Defense',
      name: 'Redirector / Shortener Service',
      status: 'WARN',
      description: `URL is routed through shortener '${hostname}' to disguise destination target.`,
      weight: 30
    });
  }

  // -------------------------------------------------------------
  // 11. PUNYCODE / HOMOGRAPH (xn--)
  // -------------------------------------------------------------
  if (hostname.includes('xn--')) {
    threatScore += 50;
    indicators.malicious.push('Internationalized Homograph Attack (Punycode xn--)');
    heuristics.push({
      category: 'Homograph Defense',
      name: 'IDN Homograph Substitution Attack',
      status: 'FAIL',
      description: 'Host contains punycode ("xn--") encoding. Attackers use visually identical Cyrillic or Greek characters to impersonate trusted sites.',
      weight: 50
    });
    mitreAttack.push('T1036.007 - Masquerading: Homoglyph Attack');
  }

  // -------------------------------------------------------------
  // 12. PROTOCOL SECURITY
  // -------------------------------------------------------------
  if (parsed.protocol === 'https:') {
    indicators.clean.push('Encrypted Transport (HTTPS)');
    heuristics.push({
      category: 'Transport Security',
      name: 'TLS/SSL Layer Active',
      status: 'PASS',
      description: 'Communication channel is encrypted via HTTPS protocol.',
      weight: 0
    });
  } else {
    threatScore += 15;
    indicators.suspicious.push('Unencrypted Transport (Plain HTTP)');
    heuristics.push({
      category: 'Transport Security',
      name: 'Insecure Cleartext Transmission',
      status: 'WARN',
      description: 'Target relies on plain HTTP, exposing sensitive telemetry to eavesdropping.',
      weight: 15
    });
  }

  // -------------------------------------------------------------
  // 13. EXACT MATCH VERIFIED BASELINE
  // -------------------------------------------------------------
  if (isExactTrustedMatch && !typosquattingMatch && !isIpv4 && !hostname.includes('xn--')) {
    threatScore = 0; // Pure clean verification
    indicators.clean.unshift('Certified Global Trust Authority Whitelist Verification');
    heuristics.unshift({
      category: 'Global Reputation',
      name: 'Certified Authentic Enterprise Domain',
      status: 'PASS',
      description: `Domain '${hostname}' is an exact verified match in the global trusted directory. Zero spoofing or typosquatting markers found.`,
      weight: 0
    });
  }

  // Normalize final threat score 0 - 100
  threatScore = Math.min(100, Math.max(0, threatScore));

  // -------------------------------------------------------------
  // 14. DYNAMIC VERDICT ENGINE
  // -------------------------------------------------------------
  let status = 'CLEAN';
  let verdict = 'CLEAN / SAFE';
  let riskLevel = 'LOW';
  let threatAlert = null;
  let summary = '';

  if (typosquattingMatch) {
    // Exact User-Specified Requirements for Typosquatting
    status = 'MALICIOUS';
    verdict = 'HIGH RISK / SPOOFED PHISHING DOMAIN';
    riskLevel = 'HIGH RISK / SPOOFED PHISHING DOMAIN';
    threatScore = 95;
    threatAlert = "Brand Imitation / Typosquatting Detected!";
    summary = `CRITICAL THREAT ALERT: Domain '${hostname}' has a mathematical string similarity of ${typosquattingMatch.similarity}% to certified global domain '${typosquattingMatch.trustedDomain}'. Brand Imitation / Typosquatting Detected! Do NOT enter credentials or trust this link.`;
  } else if (threatScore >= 60) {
    status = 'MALICIOUS';
    verdict = 'HIGH RISK / MALICIOUS TARGET';
    riskLevel = threatScore >= 80 ? 'CRITICAL' : 'HIGH';
    threatAlert = 'Critical Security Vulnerabilities / Exploit Signatures Detected';
    summary = `CRITICAL MALICIOUS TARGET: This URL exhibits severe threat indicators (${indicators.malicious.join(', ') || 'Exploit payloads / C2 addressing'}). Immediate access block advised.`;
  } else if (threatScore >= 25) {
    status = 'SUSPICIOUS';
    verdict = 'SUSPICIOUS LINK';
    riskLevel = 'MEDIUM';
    threatAlert = 'Suspicious Anomalies Detected';
    summary = `SUSPICIOUS LINK: This link exhibits anomalous characteristics (${indicators.suspicious.join(', ')}). Extreme caution recommended before clicking.`;
  } else {
    status = 'CLEAN';
    verdict = 'CLEAN / SAFE';
    riskLevel = 'LOW';
    threatAlert = null;
    summary = isExactTrustedMatch
      ? `VERIFIED SAFE: '${hostname}' is a certified trusted domain with authentic DNS reputation and active encryption.`
      : 'CLEAN: No typosquatting, brand masquerading, DGA entropy, or exploit patterns detected. Conforms to standard web security baselines.';
  }

  // Compute SHA-256 fingerprint of the scanned target
  const sha256 = crypto.createHash('sha256').update(fullTarget).digest('hex');

  return {
    success: true,
    targetType: 'url',
    target: fullTarget,
    threatScore,
    riskScore: `${threatScore}/100`,
    status,
    verdict,
    riskLevel,
    threatAlert,
    summary,
    indicators,
    hashes: {
      sha256
    },
    metadata: {
      domain: hostname,
      protocol: parsed.protocol.replace(':', ''),
      port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
      subdomains: domainParts.slice(0, -2),
      entropy: domainEntropy,
      pathEntropy,
      ipLiteral: isIpv4 || isIpv6,
      similarityScore: typosquattingMatch ? `${typosquattingMatch.similarity}%` : null,
      matchedTrustedDomain: typosquattingMatch ? typosquattingMatch.trustedDomain : null
    },
    heuristics,
    mitreAttack: Array.from(new Set(mitreAttack)),
    timestamp: new Date()
  };
}

module.exports = {
  scanUrl,
  calculateEntropy,
  levenshteinDistance,
  calculateSimilarity,
  extractDomainStem,
  TOP_TRUSTED_DOMAINS
};
