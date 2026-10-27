// Deep, live URL analysis. Complements the C++ static analyzer + ML model.
//
// Key principle: HTTPS is NOT a trust signal. Free DV certificates mean most
// phishing sites have a valid padlock, so instead of asking "is it https?"
// we look at what the certificate, domain, DNS, redirect chain and page
// content actually reveal.
//
// Every check is best-effort with timeouts: an unreachable site, a blocked
// RDAP/DNS lookup or a bot-blocking target never fails the whole scan.
const axios = require('axios');
const tls = require('tls');
const https = require('https');
const dns = require('dns').promises;
const { URL } = require('url');
const { getDomain, getPublicSuffix } = require('tldts');

const BRAND_KEYWORDS = ['paypal', 'bank', 'amazon', 'microsoft', 'google', 'netflix', 'irctc', 'income tax', 'apple', 'facebook',
  'instagram', 'whatsapp', 'linkedin', 'outlook', 'office 365', 'sbi', 'hdfc', 'icici', 'axis bank', 'kotak', 'paytm', 'phonepe',
  'flipkart', 'uidai', 'aadhaar', 'dhl', 'fedex', 'docusign', 'dropbox', 'adobe', 'coinbase', 'binance', 'metamask'];
const OFFICIAL_DOMAINS = {
  paypal: ['paypal.com'], google: ['google.com', 'google.co.in', 'gmail.com', 'youtube.com'], microsoft: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com', 'outlook.com'],
  outlook: ['outlook.com', 'live.com', 'office.com', 'microsoft.com'], 'office 365': ['office.com', 'microsoft.com', 'microsoftonline.com'],
  amazon: ['amazon.com', 'amazon.in'], netflix: ['netflix.com'], apple: ['apple.com', 'icloud.com'], facebook: ['facebook.com', 'fb.com', 'meta.com'],
  instagram: ['instagram.com'], whatsapp: ['whatsapp.com'], linkedin: ['linkedin.com'], irctc: ['irctc.co.in'], 'income tax': ['incometax.gov.in'],
  sbi: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com'], hdfc: ['hdfcbank.com'], icici: ['icicibank.com'], 'axis bank': ['axisbank.com'], kotak: ['kotak.com'],
  paytm: ['paytm.com'], phonepe: ['phonepe.com'], flipkart: ['flipkart.com'], uidai: ['uidai.gov.in'], aadhaar: ['uidai.gov.in'], dhl: ['dhl.com'],
  fedex: ['fedex.com'], docusign: ['docusign.com', 'docusign.net'], dropbox: ['dropbox.com'], adobe: ['adobe.com'], coinbase: ['coinbase.com'],
  binance: ['binance.com'], metamask: ['metamask.io'],
};
const FREE_DV_ISSUERS = ["let's encrypt", 'zerossl', 'buypass', 'google trust services', 'cpanel', 'ssl.com free'];
const DYNAMIC_DNS = ['duckdns.org', 'no-ip.com', 'noip.com', 'dynu.com', 'afraid.org', 'ddns.net', 'hopto.org', 'zapto.org'];
// Fetch pages even when their certificate is invalid: we still need to see
// the content, and certificate problems are reported separately by
// inspectCertificate(). Nothing is ever submitted to the site.
const scanAgent = new https.Agent({ rejectUnauthorized: false });
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36 CyberGuard-Scanner/2.0';

function safeHost(u) {
  try { return new URL(u).hostname.toLowerCase(); } catch (e) { return null; }
}
function registrable(host) {
  if (!host) return null;
  return getDomain(host, { allowPrivateDomains: true }) || host;
}
function withTimeout(promise, ms, fallback) {
  return Promise.race([promise, new Promise((resolve) => setTimeout(() => resolve(fallback), ms))]);
}

// ------------------------------------------------------------ redirects --
// Follows HTTP redirects hop by hop (so every hop is visible), plus one
// client-side meta-refresh. Kept backward compatible with the old API.
async function followRedirects(url, maxHops = 10) {
  const chain = [];
  let current = url;
  let response = null;
  try {
    for (let hop = 0; hop <= maxHops; hop++) {
      response = await axios.get(current, {
        maxRedirects: 0, timeout: 7000, validateStatus: () => true, responseType: 'text', httpsAgent: scanAgent,
        headers: { 'User-Agent': UA, Accept: 'text/html,application/xhtml+xml' }, maxContentLength: 3 * 1024 * 1024,
      });
      const location = response.headers?.location;
      chain.push({ url: current, status: response.status, location: location || null });
      if (response.status >= 300 && response.status < 400 && location) {
        current = new URL(location, current).toString();
        continue;
      }
      // client-side meta refresh (follow once)
      const html = typeof response.data === 'string' ? response.data : '';
      const meta = html.match(/<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']?\s*\d+\s*;\s*url\s*=\s*([^"'>\s]+)/i);
      if (meta && hop < maxHops && !chain.some((c) => c.meta)) {
        chain[chain.length - 1].meta = true;
        current = new URL(meta[1], current).toString();
        continue;
      }
      break;
    }
    const finalUrl = current;
    const originalHost = safeHost(url);
    const finalHost = safeHost(finalUrl);
    const html = typeof response?.data === 'string' ? response.data.slice(0, 400000) : '';
    return {
      reachable: true,
      finalUrl,
      redirectedToDifferentHost: Boolean(finalHost && originalHost && finalHost !== originalHost),
      crossDomain: Boolean(finalHost && originalHost && registrable(finalHost) !== registrable(originalHost)),
      httpStatus: response?.status,
      chain,
      headers: response?.headers || {},
      html,
    };
  } catch (e) {
    // A later hop failing still means the link was live: report the chain so
    // far (the destination may be taken down, geo-blocked or bot-blocking).
    if (chain.length) {
      const originalHost = safeHost(url);
      const lastHost = safeHost(current);
      return {
        reachable: true, partial: true, error: e.code || e.message, finalUrl: current, chain, html: '', headers: {},
        redirectedToDifferentHost: Boolean(lastHost && originalHost && lastHost !== originalHost),
        crossDomain: Boolean(lastHost && originalHost && registrable(lastHost) !== registrable(originalHost)),
        httpStatus: chain[chain.length - 1].status,
      };
    }
    return { reachable: false, error: e.code || e.message, chain };
  }
}

// ---------------------------------------------------------- certificate --
function inspectCertificate(hostname) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname, timeout: 6000, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      if (!cert || !Object.keys(cert).length) { socket.end(); return finish({ present: false }); }
      const now = new Date();
      const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
      const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
      const issuer = cert.issuer?.O || cert.issuer?.CN || null;
      const san = (cert.subjectaltname || '').split(',').map((s) => s.trim().replace(/^DNS:/, '')).filter(Boolean);
      const idErr = tls.checkServerIdentity(hostname, cert);
      finish({
        present: true,
        issuer,
        issuerCN: cert.issuer?.CN || null,
        subject: cert.subject?.CN || null,
        subjectAltNames: san.slice(0, 20),
        selfSigned: Boolean(cert.issuer && cert.subject && cert.issuer.CN === cert.subject.CN && cert.issuer.O === cert.subject.O),
        validFrom: cert.valid_from || null,
        validTo: cert.valid_to || null,
        ageDays: validFrom ? Math.floor((now - validFrom) / 86400000) : null,
        validityDays: validFrom && validTo ? Math.round((validTo - validFrom) / 86400000) : null,
        expired: validTo ? now > validTo : null,
        notYetValid: validFrom ? now < validFrom : null,
        hostnameMatches: !idErr,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        freeDvIssuer: FREE_DV_ISSUERS.some((f) => (issuer || '').toLowerCase().includes(f)),
      });
      socket.end();
    });
    socket.on('error', (e) => finish({ present: false, error: e.code || 'unreachable' }));
    socket.setTimeout(6000, () => { socket.destroy(); finish({ present: false, error: 'timeout' }); });
  });
}

// ------------------------------------------------------------------ DNS --
async function inspectDns(hostname) {
  const out = { resolved: false };
  const tryIt = async (fn) => { try { return await fn(); } catch (e) { return null; } };
  const [a, aaaa, mx, ns, txt, cname] = await Promise.all([
    tryIt(() => dns.resolve4(hostname, { ttl: true })),
    tryIt(() => dns.resolve6(hostname)),
    tryIt(() => dns.resolveMx(registrable(hostname))),
    tryIt(() => dns.resolveNs(registrable(hostname))),
    tryIt(() => dns.resolveTxt(registrable(hostname))),
    tryIt(() => dns.resolveCname(hostname)),
  ]);
  out.resolved = Boolean((a && a.length) || (aaaa && aaaa.length) || (cname && cname.length));
  out.a = (a || []).map((r) => r.address);
  out.minTtl = a && a.length ? Math.min(...a.map((r) => r.ttl)) : null;
  out.aaaa = aaaa || [];
  out.cname = cname || [];
  out.mx = (mx || []).map((m) => m.exchange);
  out.ns = ns || [];
  out.spf = (txt || []).map((t) => t.join('')).find((t) => t.startsWith('v=spf1')) || null;
  return out;
}

// ----------------------------------------------------------- domain age --
async function domainAge(domain) {
  try {
    const { data } = await axios.get(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      timeout: 7000, headers: { Accept: 'application/rdap+json', 'User-Agent': UA }, maxRedirects: 5,
    });
    const reg = (data.events || []).find((e) => e.eventAction === 'registration');
    const exp = (data.events || []).find((e) => e.eventAction === 'expiration');
    const registrar = (data.entities || []).find((e) => (e.roles || []).includes('registrar'));
    const registrarName = registrar?.vcardArray?.[1]?.find((v) => v[0] === 'fn')?.[3] || null;
    const created = reg ? new Date(reg.eventDate) : null;
    return {
      available: true,
      registered: reg?.eventDate || null,
      expires: exp?.eventDate || null,
      ageDays: created ? Math.floor((Date.now() - created) / 86400000) : null,
      registrar: registrarName,
    };
  } catch (e) {
    return { available: false, error: e.response?.status === 404 ? 'domain not found in RDAP' : (e.code || e.message) };
  }
}

// ------------------------------------------------------- page forensics --
function detectFakeLoginPage(html, hostname) {
  if (!html) return { hasPasswordField: false, brandMismatch: false };
  const lower = html.toLowerCase();
  const hasPasswordField = /<input[^>]*type\s*=\s*["']?password/i.test(html);
  const reg = registrable(hostname || '') || '';
  let brandMismatch = false;
  let mentionedBrand = null;
  const title = (html.match(/<title[^>]*>([^<]{0,200})/i) || [])[1] || '';
  for (const brand of BRAND_KEYWORDS) {
    const inTitle = title.toLowerCase().includes(brand);
    if ((inTitle || lower.includes(brand)) && !(OFFICIAL_DOMAINS[brand] || []).includes(reg) && !reg.includes(brand.replace(' ', ''))) {
      brandMismatch = true;
      mentionedBrand = brand;
      if (inTitle) break;
    }
  }
  return { hasPasswordField, brandMismatch, mentionedBrand, title: title.trim() };
}

function analyzePage(html, pageUrl) {
  const host = safeHost(pageUrl) || '';
  const reg = registrable(host);
  const out = { forms: [], passwordFields: 0, cardFields: 0, otpFields: 0, hiddenIframes: 0, obfuscatedScripts: [], externalResourceRatio: 0,
    externalFavicon: false, disablesRightClick: false, jsRedirect: false, dataUriEmbeds: 0 };
  if (!html) return out;
  out.passwordFields = (html.match(/<input[^>]*type\s*=\s*["']?password/gi) || []).length;
  out.cardFields = (html.match(/<input[^>]*(name|id|autocomplete)\s*=\s*["']?[^"'>]*(cc-number|cardnumber|card_number|cvv|cvc|ccnum|expiry)/gi) || []).length;
  out.otpFields = (html.match(/<input[^>]*(name|id|autocomplete|placeholder)\s*=\s*["']?[^"'>]*(otp|one-time-code|mpin|upi pin)/gi) || []).length;
  for (const m of html.matchAll(/<form[^>]*>/gi)) {
    const action = (m[0].match(/action\s*=\s*["']?([^"'\s>]*)/i) || [])[1] || '';
    let actionHost = host;
    try { if (action && !action.startsWith('#')) actionHost = new URL(action, pageUrl).hostname; } catch (e) { /* ignore */ }
    out.forms.push({ action: action.slice(0, 200), actionHost, external: registrable(actionHost) !== reg, method: ((m[0].match(/method\s*=\s*["']?(\w+)/i) || [])[1] || 'get').toLowerCase() });
  }
  out.hiddenIframes = (html.match(/<iframe[^>]*(width\s*=\s*["']?0|height\s*=\s*["']?0|display\s*:\s*none|visibility\s*:\s*hidden)/gi) || []).length;
  const obf = [
    ['eval(atob(', /eval\s*\(\s*atob\s*\(/i], ['document.write(unescape(', /document\.write\s*\(\s*unescape\s*\(/i],
    ['long String.fromCharCode chain', /String\.fromCharCode\s*\((\s*\d+\s*,){40,}/i], ['eval(function(p,a,c,k,e (packer)', /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e/i],
    ['very long base64 blob in script', /["'][A-Za-z0-9+/]{2000,}={0,2}["']/],
  ];
  for (const [name, re] of obf) if (re.test(html)) out.obfuscatedScripts.push(name);
  out.jsRedirect = /(window|document|top)\.location(\.href)?\s*=|location\.replace\s*\(/i.test(html);
  out.disablesRightClick = /oncontextmenu\s*=\s*["']?\s*return\s+false/i.test(html);
  out.dataUriEmbeds = (html.match(/<(iframe|script|object|embed)[^>]*src\s*=\s*["']?data:/gi) || []).length;
  let ext = 0, total = 0;
  for (const m of html.matchAll(/<(?:script|img|link)[^>]*(?:src|href)\s*=\s*["']?([^"'\s>]+)/gi)) {
    const ref = m[1];
    if (ref.startsWith('data:') || ref.startsWith('#')) continue;
    total++;
    try { if (registrable(new URL(ref, pageUrl).hostname) !== reg) ext++; } catch (e) { /* ignore */ }
  }
  out.externalResourceRatio = total ? ext / total : 0;
  out.resourceCount = total;
  const fav = html.match(/<link[^>]*rel\s*=\s*["']?[^"'>]*icon[^>]*href\s*=\s*["']?([^"'\s>]+)/i);
  if (fav) { try { out.externalFavicon = registrable(new URL(fav[1], pageUrl).hostname) !== reg; out.faviconHost = new URL(fav[1], pageUrl).hostname; } catch (e) { /* ignore */ } }
  return out;
}

// -------------------------------------------------------- safe browsing --
async function safeBrowsingLookup(url) {
  const key = process.env.SAFE_BROWSING_API_KEY;
  if (!key) return { checked: false, reason: 'SAFE_BROWSING_API_KEY not configured' };
  try {
    const { data } = await axios.post(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${key}`, {
      client: { clientId: 'cyberguard', clientVersion: '2.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url }],
      },
    }, { timeout: 6000 });
    return { checked: true, matches: (data.matches || []).map((m) => m.threatType) };
  } catch (e) {
    return { checked: false, reason: e.response?.data?.error?.message || e.message };
  }
}

// ------------------------------------------------------------ orchestrate --
async function liveCheck(inputUrl) {
  // Offline mode: never contact the target site, DNS or RDAP.
  if (!require('./systemMode').isOnline()) return null;
  let url = inputUrl.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) url = `https://${url}`;
  const hostname = safeHost(url);
  const findings = [];
  let score = 0;
  const add = (indicator, detail, weight) => { findings.push({ indicator, detail, weight }); score += weight; };

  const regDomain = registrable(hostname);
  const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(hostname || '');
  const [redirectResult, dnsInfo, ageInfo, sbInfo] = await Promise.all([
    followRedirects(url),
    hostname && !isIp ? withTimeout(inspectDns(hostname), 6000, { resolved: false, error: 'timeout' }) : Promise.resolve({ resolved: isIp }),
    regDomain && !isIp ? withTimeout(domainAge(regDomain), 8000, { available: false, error: 'timeout' }) : Promise.resolve({ available: false }),
    safeBrowsingLookup(url),
  ]);
  // A plain-http URL that fails may still be served over https (and vice versa).
  let redirects = redirectResult;
  // Domain does not exist in DNS: any HTTP answer came from a proxy/captive
  // portal (its error page), not from the site - do not analyse it as the site.
  const hostMissing = hostname && !isIp && dnsInfo && !dnsInfo.resolved && !dnsInfo.error;
  if (hostMissing && redirects.reachable && !process.env.LIVE_CHECK_TRUST_PROXY) {
    redirects = { reachable: false, error: 'ENOTFOUND (domain does not resolve; proxy response ignored)', chain: [] };
  }
  if (!redirects.reachable && !hostMissing && url.startsWith('https://')) {
    const alt = await followRedirects(url.replace(/^https:/, 'http:'));
    if (alt.reachable) redirects = alt;
  }
  const finalUrl = redirects.finalUrl || url;
  const finalHost = safeHost(finalUrl);
  const certHost = finalUrl.startsWith('https://') ? finalHost : hostname;
  const certHostIsIp = /^\d+\.\d+\.\d+\.\d+$/.test(certHost || '');
  const certResult = certHost && !certHostIsIp && !hostMissing ? await inspectCertificate(certHost) : { present: false };

  // --- redirects
  const hops = (redirects.chain || []).filter((c) => c.location || c.meta);
  if (redirects.reachable && redirects.crossDomain)
    add('malicious_redirect', `Link redirects through ${hops.length} hop(s) and ends on a different site (${registrable(finalHost)}) than the one shown (${regDomain})`, 30);
  else if (hops.length >= 3) add('long_redirect_chain', `Link bounces through ${hops.length} redirects before landing`, 10);
  if ((redirects.chain || []).some((c) => c.meta)) add('meta_refresh_redirect', 'Page uses an HTML meta-refresh to forward visitors elsewhere', 10);

  // --- certificate (HTTPS alone never lowers the score)
  if (certResult.present) {
    if (certResult.expired) add('expired_certificate', "The site's TLS certificate has expired", 25);
    if (certResult.selfSigned) add('self_signed_certificate', 'The site presents a self-signed certificate rather than one issued by a trusted authority', 30);
    else if (certResult.authorized === false) add('untrusted_certificate_chain', `The certificate chain could not be verified (${certResult.authorizationError || 'untrusted'})`, 20);
    if (!certResult.hostnameMatches) add('certificate_hostname_mismatch', `Certificate is not valid for ${certHost} (issued for ${certResult.subject || 'another name'})`, 30);
    if (certResult.ageDays !== null && certResult.ageDays <= 7) add('brand_new_certificate', `TLS certificate was issued only ${certResult.ageDays} day(s) ago - phishing kits usually get a fresh free certificate right before a campaign`, 20);
    else if (certResult.ageDays !== null && certResult.ageDays <= 30) add('recent_certificate', `TLS certificate is only ${certResult.ageDays} days old`, 8);
    add('https_is_not_trust', `The padlock only shows the connection is encrypted (issuer: ${certResult.issuer || 'unknown'}${certResult.freeDvIssuer ? ', a free automated certificate that anyone can get in seconds' : ''}); it does not prove who runs the site`, 0);
  } else if (redirects.reachable && finalUrl.startsWith('http://')) {
    add('no_tls', 'Site is served without HTTPS - passwords would travel in plain text', 10);
  }

  // --- DNS
  if (dnsInfo && !dnsInfo.resolved && !dnsInfo.error) add('does_not_resolve', `${hostname} does not resolve in DNS (taken down, or not yet live)`, 5);
  if (dnsInfo?.a && dnsInfo.a.length >= 8 && dnsInfo.minTtl !== null && dnsInfo.minTtl < 300)
    add('fast_flux_dns', `${dnsInfo.a.length} IP addresses with a ${dnsInfo.minTtl}s TTL - a fast-flux pattern used to keep malicious sites online`, 15);
  if ((dnsInfo?.ns || []).some((ns) => DYNAMIC_DNS.some((d) => ns.toLowerCase().endsWith(d))))
    add('dynamic_dns_nameserver', 'Domain uses a free dynamic-DNS provider for its name servers', 10);

  // --- domain age
  if (ageInfo?.available && ageInfo.ageDays !== null) {
    if (ageInfo.ageDays < 30) add('newly_registered_domain', `Domain ${regDomain} was registered only ${ageInfo.ageDays} day(s) ago (${String(ageInfo.registered).slice(0, 10)})`, 30);
    else if (ageInfo.ageDays < 180) add('young_domain', `Domain ${regDomain} is only ${ageInfo.ageDays} days old`, 10);
  }

  // --- page content
  const loginPageResult = detectFakeLoginPage(redirects.html, finalHost || hostname || '');
  const page = analyzePage(redirects.html, finalUrl);
  if (loginPageResult.hasPasswordField && loginPageResult.brandMismatch)
    add('fake_login_page', `Page asks for a password while presenting itself as "${loginPageResult.mentionedBrand}" on an unrelated domain (${registrable(finalHost)})`, 40);
  if (page.forms.some((f) => f.external) && (page.passwordFields || page.cardFields || page.otpFields))
    add('credentials_posted_elsewhere', `Login/payment form submits to a different site (${page.forms.find((f) => f.external).actionHost})`, 25);
  if (page.cardFields) add('card_details_requested', `Page contains ${page.cardFields} payment-card field(s) (card number / CVV / expiry)`, loginPageResult.brandMismatch ? 20 : 5);
  if (page.otpFields) add('otp_requested', 'Page asks for an OTP / UPI PIN / MPIN', loginPageResult.brandMismatch ? 20 : 5);
  if (page.obfuscatedScripts.length) add('obfuscated_javascript', `Obfuscated JavaScript detected: ${page.obfuscatedScripts.join(', ')}`, 15);
  if (page.hiddenIframes) add('hidden_iframe', `${page.hiddenIframes} invisible iframe(s) on the page`, 10);
  if (page.dataUriEmbeds) add('data_uri_embed', 'Scripts/frames are embedded as data: URIs (hides content from scanners)', 10);
  if (page.resourceCount >= 5 && page.externalResourceRatio >= 0.8 && loginPageResult.hasPasswordField)
    add('cloned_page_assets', `${Math.round(page.externalResourceRatio * 100)}% of the page's images/scripts load from other sites - typical of a copied login page`, 10);
  if (page.externalFavicon && loginPageResult.brandMismatch) add('borrowed_favicon', `Favicon is loaded from ${page.faviconHost}`, 5);
  if (page.disablesRightClick) add('right_click_disabled', 'Page disables right-click (hinders inspection)', 5);

  // --- reputation
  if (sbInfo.checked && sbInfo.matches.length) add('google_safe_browsing_match', `Google Safe Browsing lists this URL as ${sbInfo.matches.join(', ')}`, 60);

  return {
    reachable: redirects.reachable,
    partial: Boolean(redirects.partial),
    error: redirects.error,
    finalUrl,
    redirectChain: (redirects.chain || []).map((c) => ({ url: c.url, status: c.status, location: c.location, metaRefresh: Boolean(c.meta) })),
    crossDomainRedirect: Boolean(redirects.crossDomain),
    httpStatus: redirects.httpStatus,
    certificate: certResult,
    dns: dnsInfo,
    domainAge: ageInfo,
    registrableDomain: regDomain,
    publicSuffix: hostname ? getPublicSuffix(hostname, { allowPrivateDomains: true }) : null,
    loginPage: loginPageResult,
    page,
    safeBrowsing: sbInfo,
    findings,
    score: Math.min(100, score),
  };
}

module.exports = { liveCheck, followRedirects, inspectCertificate, detectFakeLoginPage, analyzePage, inspectDns, domainAge, registrable };
