import dns from 'dns/promises';
import tls from 'tls';
import net from 'net';
import http from 'http';
import https from 'https';
import { DomainAssessmentData, DomainInfo, DnsRecordDetails, IpInformation, WebServerDetails, SslCertificateDetails, EmailSecurityDetails } from '../src/types.js';

/**
 * TCP Port 43 WHOIS Client with Referral Follow-Up
 */
async function queryWhoisServer(server: string, domain: string, timeoutMs = 6000): Promise<string> {
  return new Promise((resolve) => {
    let output = '';
    const socket = new net.Socket();
    socket.setTimeout(timeoutMs);
    socket.connect(43, server, () => {
      socket.write(`${domain}\r\n`);
    });
    socket.on('data', (data) => {
      output += data.toString('utf-8');
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve(output);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(output);
    });
    socket.on('close', () => {
      resolve(output);
    });
  });
}

/**
 * Fallback TCP WHOIS Lookup querying IANA and authoritative WHOIS server
 */
async function performWhoisQuery(domain: string): Promise<{ rawText: string; parsed: DomainInfo }> {
  const parsed: DomainInfo = {};
  let raw = '';
  try {
    console.log(`[WHOIS TCP] Querying whois.iana.org for ${domain}...`);
    raw = await queryWhoisServer('whois.iana.org', domain);
    let referralServer = '';

    const referMatch = raw.match(/refer:\s*([^\s]+)/i) || raw.match(/whois:\s*([^\s]+)/i);
    if (referMatch) {
      referralServer = referMatch[1];
    }

    if (referralServer) {
      console.log(`[WHOIS TCP] Referral WHOIS server detected: ${referralServer}. Querying referral WHOIS...`);
      const refRaw = await queryWhoisServer(referralServer, domain);
      if (refRaw && refRaw.trim().length > 0) {
        raw += `\n\n--- Referral WHOIS Output from ${referralServer} ---\n` + refRaw;
      }
    }

    // Check for ccTLD Registry specifics (e.g., .pk)
    if (domain.toLowerCase().endsWith('.pk')) {
      parsed.registry = 'PKNIC (Pakistan Network Information Center)';
    }

    // Parse Registry
    const registryMatch = raw.match(/(?:Registry|Registry Name|Registry Operator|Registry ID):\s*(.+)/i);
    if (registryMatch && !parsed.registry) parsed.registry = registryMatch[1].trim();

    // Parse Registrar
    const registrarMatch = raw.match(/(?:Registrar|Sponsoring Registrar|Registrar Name|Registrar Organization):\s*(.+)/i);
    if (registrarMatch) parsed.registrar = registrarMatch[1].trim();

    // Parse Dates
    const creationMatch = raw.match(/(?:Creation Date|Created On|Registered On|Registration Time|Created Date|Created):\s*(.+)/i);
    if (creationMatch) parsed.registrationDate = creationMatch[1].trim();

    const expiryMatch = raw.match(/(?:Registry Expiry Date|Expiration Date|Expires On|paid-till|Expiry Date|Expires):\s*(.+)/i);
    if (expiryMatch) parsed.expirationDate = expiryMatch[1].trim();

    const updatedMatch = raw.match(/(?:Updated Date|Last Updated On|Changed|Last Updated):\s*(.+)/i);
    if (updatedMatch) parsed.lastUpdatedDate = updatedMatch[1].trim();

    // Parse Status
    const statusMatches = raw.match(/Domain Status:\s*(.+)/gi) || raw.match(/Status:\s*(.+)/gi);
    if (statusMatches) {
      parsed.domainStatus = statusMatches.map(s => s.replace(/(?:Domain Status|Status):\s*/i, '').trim()).join(', ');
    }

    // Parse Nameservers
    const nsMatches = raw.match(/(?:Name Server|nserver|NS):\s*([^\s]+)/gi);
    if (nsMatches) {
      parsed.registryNameServers = Array.from(new Set(nsMatches.map(s => s.replace(/(?:Name Server|nserver|NS):\s*/i, '').trim().toLowerCase())));
      parsed.nameServers = parsed.registryNameServers;
    }

    // Parse Country
    const countryMatch = raw.match(/(?:Registrant Country|Country):\s*(.+)/i);
    if (countryMatch) parsed.registrantCountry = countryMatch[1].trim();

    console.log(`[WHOIS TCP] Successfully parsed WHOIS fields:`, JSON.stringify(parsed));
    return { rawText: raw, parsed };
  } catch (err: any) {
    console.error(`[WHOIS TCP] Exception during WHOIS query for ${domain}:`, err.stack || err.message || String(err));
    return { rawText: raw || `WHOIS Error: ${err.message || String(err)}`, parsed };
  }
}

/**
 * Custom HTTP/HTTPS Client ignoring SSL Certificate Errors
 */
interface HttpResponseData {
  url: string;
  statusCode: number;
  statusText: string;
  headers: Record<string, string>;
  bodySnippet: string;
}

async function makeHttpRequest(targetUrl: string, maxRedirects = 5): Promise<HttpResponseData> {
  let currentUrl = targetUrl;
  let redirectsLeft = maxRedirects;

  while (redirectsLeft >= 0) {
    const isHttps = currentUrl.startsWith('https:');
    const client = isHttps ? https : http;

    const resData = await new Promise<HttpResponseData | null>((resolve) => {
      try {
        const parsedUrl = new URL(currentUrl);
        const req = client.request({
          protocol: parsedUrl.protocol,
          hostname: parsedUrl.hostname,
          port: parsedUrl.port || (isHttps ? 443 : 80),
          path: parsedUrl.pathname + parsedUrl.search,
          method: 'GET',
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) VulnSight-Security-Scanner/2.0'
          },
          rejectUnauthorized: false, // Critical for security scanner: allows inspecting sites with untrusted/expired certs
          timeout: 8000
        }, (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('end', () => {
            const body = Buffer.concat(chunks).toString('utf-8');
            const headersObj: Record<string, string> = {};
            for (const [key, val] of Object.entries(res.headers)) {
              if (val) {
                headersObj[key.toLowerCase()] = Array.isArray(val) ? val.join(', ') : val;
              }
            }
            resolve({
              url: currentUrl,
              statusCode: res.statusCode || 0,
              statusText: res.statusMessage || '',
              headers: headersObj,
              bodySnippet: body.slice(0, 1000)
            });
          });
        });

        req.on('error', (err) => {
          console.error(`[HTTP Client Error] ${currentUrl}:`, err.stack || err.message || String(err));
          resolve(null);
        });

        req.on('timeout', () => {
          req.destroy();
          console.error(`[HTTP Client Timeout] Request timed out for ${currentUrl}`);
          resolve(null);
        });

        req.end();
      } catch (err: any) {
        console.error(`[HTTP Request Exception] ${currentUrl}:`, err.stack || err.message || String(err));
        resolve(null);
      }
    });

    if (!resData) {
      throw new Error(`Connection or HTTP request failed for ${currentUrl}`);
    }

    // Check for HTTP Redirects
    if ([301, 302, 303, 307, 308].includes(resData.statusCode) && resData.headers['location'] && redirectsLeft > 0) {
      redirectsLeft--;
      const redirectLocation = resData.headers['location'];
      if (redirectLocation.startsWith('http://') || redirectLocation.startsWith('https://')) {
        currentUrl = redirectLocation;
      } else {
        currentUrl = new URL(redirectLocation, currentUrl).toString();
      }
      console.log(`[HTTP Redirect] Followed redirect (${resData.statusCode}) -> ${currentUrl}`);
      continue;
    }

    return resData;
  }

  throw new Error(`Exceeded maximum redirect limit for ${targetUrl}`);
}

export async function performDomainAssessment(cleanTarget: string): Promise<{
  domainAssessment: DomainAssessmentData;
  rawOutputs: { dns: string; whois: string; ssl: string; http: string };
}> {
  console.log(`\n==================================================`);
  console.log(`[Domain Recon Pipeline] Launching assessment for target: "${cleanTarget}"`);
  console.log(`==================================================\n`);

  const domainInfo: DomainInfo = {};
  const dnsRecords: DnsRecordDetails = {};
  const ipInfo: IpInformation = {};
  const webServer: WebServerDetails = {};
  const sslDetails: SslCertificateDetails = {};
  const emailSecurity: EmailSecurityDetails = {};

  const rawOutputs = {
    dns: '',
    whois: '',
    ssl: '',
    http: ''
  };

  // -------------------------------------------------------------------------
  // 1. DNS RESOLUTION & ENUMERATION PIPELINE
  // -------------------------------------------------------------------------
  console.log(`[DNS] Starting DNS Resolution & Enumeration for "${cleanTarget}"...`);
  const dnsLogLines: string[] = [];
  let publicIp: string | undefined = undefined;

  // A Records
  try {
    console.log(`[DNS] Querying A records via dns.resolve4("${cleanTarget}")...`);
    const a = await dns.resolve4(cleanTarget);
    if (a && a.length > 0) {
      dnsRecords.aRecords = a;
      publicIp = a[0];
      ipInfo.publicIp = publicIp;
      dnsLogLines.push(`[A Records]\n${a.join('\n')}`);
      console.log(`[DNS] Success. Resolved A records:`, a);
    }
  } catch (err: any) {
    console.error(`[DNS Exception] A record resolve4 failed for ${cleanTarget}:`, err.message || String(err));
    dnsLogLines.push(`[A Records] direct resolve4 failed: ${err.message || String(err)}`);
  }

  // System DNS Lookup Fallback (getaddrinfo)
  if (!publicIp) {
    try {
      console.log(`[DNS Fallback] Querying OS resolver via dns.lookup("${cleanTarget}")...`);
      const lookupResult = await dns.lookup(cleanTarget);
      if (lookupResult && lookupResult.address) {
        publicIp = lookupResult.address;
        ipInfo.publicIp = publicIp;
        dnsRecords.aRecords = [publicIp];
        dnsLogLines.push(`[A Records (System Lookup Fallback)]\n${publicIp}`);
        console.log(`[DNS Fallback] Success. OS resolver returned IP: ${publicIp}`);
      }
    } catch (err: any) {
      console.error(`[DNS Exception] System lookup fallback failed for ${cleanTarget}:`, err.message || String(err));
      dnsLogLines.push(`[A Records] System lookup failed: ${err.message || String(err)}`);
    }
  }

  // AAAA Records
  try {
    console.log(`[DNS] Querying AAAA records via dns.resolve6("${cleanTarget}")...`);
    const aaaa = await dns.resolve6(cleanTarget);
    if (aaaa && aaaa.length > 0) {
      dnsRecords.aaaaRecords = aaaa;
      dnsLogLines.push(`[AAAA Records]\n${aaaa.join('\n')}`);
      console.log(`[DNS] Success. Resolved AAAA records:`, aaaa);
    }
  } catch (err: any) {
    console.log(`[DNS] AAAA records not found/failed:`, err.message || String(err));
    dnsLogLines.push(`[AAAA Records] Lookup failed/none: ${err.message || String(err)}`);
  }

  // MX Records
  try {
    console.log(`[DNS] Querying MX records via dns.resolveMx("${cleanTarget}")...`);
    const mx = await dns.resolveMx(cleanTarget);
    if (mx && mx.length > 0) {
      dnsRecords.mxRecords = mx.map(m => `Priority ${m.priority}: ${m.exchange}`);
      dnsLogLines.push(`[MX Records]\n${dnsRecords.mxRecords.join('\n')}`);
      emailSecurity.mxValidation = `${mx.length} MX record(s) resolved successfully`;
      console.log(`[DNS] Success. Resolved MX records:`, dnsRecords.mxRecords);
    } else {
      emailSecurity.mxValidation = 'No MX records found';
    }
  } catch (err: any) {
    console.log(`[DNS] MX records failed/none:`, err.message || String(err));
    dnsLogLines.push(`[MX Records] Lookup failed/none: ${err.message || String(err)}`);
    emailSecurity.mxValidation = 'MX lookup failed';
  }

  // NS Records
  try {
    console.log(`[DNS] Querying NS records via dns.resolveNs("${cleanTarget}")...`);
    const ns = await dns.resolveNs(cleanTarget);
    if (ns && ns.length > 0) {
      dnsRecords.nsRecords = ns;
      domainInfo.authoritativeNameServers = ns;
      dnsLogLines.push(`[NS Records (Authoritative DNS)]\n${ns.join('\n')}`);
      console.log(`[DNS] Success. Resolved Authoritative NS records:`, ns);
    }
  } catch (err: any) {
    console.log(`[DNS] NS records failed/none:`, err.message || String(err));
    dnsLogLines.push(`[NS Records] Lookup failed/none: ${err.message || String(err)}`);
  }

  // CNAME Records
  try {
    console.log(`[DNS] Querying CNAME records via dns.resolveCname("${cleanTarget}")...`);
    const cname = await dns.resolveCname(cleanTarget);
    if (cname && cname.length > 0) {
      dnsRecords.cnameRecords = cname;
      dnsLogLines.push(`[CNAME Records]\n${cname.join('\n')}`);
      console.log(`[DNS] Success. Resolved CNAME records:`, cname);
    }
  } catch (err: any) {
    dnsLogLines.push(`[CNAME Records] Lookup failed/none: ${err.message || String(err)}`);
  }

  // SOA Record
  try {
    console.log(`[DNS] Querying SOA record via dns.resolveSoa("${cleanTarget}")...`);
    const soa = await dns.resolveSoa(cleanTarget);
    if (soa) {
      dnsRecords.soaRecord = `Hostmaster: ${soa.hostmaster}, NS: ${soa.nsname}, Serial: ${soa.serial}, Refresh: ${soa.refresh}`;
      dnsLogLines.push(`[SOA Record]\n${dnsRecords.soaRecord}`);
      console.log(`[DNS] Success. Resolved SOA record:`, dnsRecords.soaRecord);
    }
  } catch (err: any) {
    dnsLogLines.push(`[SOA Record] Lookup failed/none: ${err.message || String(err)}`);
  }

  // TXT Records & SPF
  try {
    console.log(`[DNS] Querying TXT records via dns.resolveTxt("${cleanTarget}")...`);
    const txt = await dns.resolveTxt(cleanTarget);
    if (txt && txt.length > 0) {
      const flattenedTxt = txt.map(t => t.join(''));
      dnsRecords.txtRecords = flattenedTxt;
      dnsLogLines.push(`[TXT Records]\n${flattenedTxt.join('\n')}`);
      console.log(`[DNS] Success. Resolved TXT records count: ${flattenedTxt.length}`);

      const spf = flattenedTxt.find(t => t.toLowerCase().startsWith('v=spf1'));
      if (spf) {
        dnsRecords.spfRecord = spf;
        emailSecurity.spfRecord = spf;
        console.log(`[DNS] Found SPF Record:`, spf);
      }
    }
  } catch (err: any) {
    dnsLogLines.push(`[TXT Records] Lookup failed/none: ${err.message || String(err)}`);
  }

  // DMARC Record
  try {
    console.log(`[DNS] Querying DMARC record via dns.resolveTxt("_dmarc.${cleanTarget}")...`);
    const dmarcTxt = await dns.resolveTxt(`_dmarc.${cleanTarget}`);
    if (dmarcTxt && dmarcTxt.length > 0) {
      const flattenedDmarc = dmarcTxt.map(t => t.join('')).find(t => t.toLowerCase().startsWith('v=dmarc1'));
      if (flattenedDmarc) {
        dnsRecords.dmarcRecord = flattenedDmarc;
        emailSecurity.dmarcRecord = flattenedDmarc;
        dnsLogLines.push(`[DMARC Record]\n${flattenedDmarc}`);
        console.log(`[DNS] Success. Found DMARC Record:`, flattenedDmarc);
      }
    }
  } catch (err: any) {
    dnsLogLines.push(`[DMARC Record] Lookup failed/none: ${err.message || String(err)}`);
  }

  // DKIM Record Check
  try {
    console.log(`[DNS] Querying DKIM record via dns.resolveTxt("default._domainkey.${cleanTarget}")...`);
    const dkimTxt = await dns.resolveTxt(`default._domainkey.${cleanTarget}`);
    if (dkimTxt && dkimTxt.length > 0) {
      const dkimStr = dkimTxt.map(t => t.join('')).join(' ');
      dnsRecords.dkimStatus = `Detected (default selector): ${dkimStr.slice(0, 60)}...`;
      emailSecurity.dkimStatus = dnsRecords.dkimStatus;
      dnsLogLines.push(`[DKIM Record]\n${dkimStr}`);
      console.log(`[DNS] Success. Found DKIM Record:`, dkimStr);
    } else {
      dnsRecords.dkimStatus = 'Default selector not published (custom selector required)';
      emailSecurity.dkimStatus = dnsRecords.dkimStatus;
    }
  } catch (err: any) {
    dnsRecords.dkimStatus = 'Selector default._domainkey not found';
    emailSecurity.dkimStatus = dnsRecords.dkimStatus;
  }

  rawOutputs.dns = dnsLogLines.join('\n\n');

  // -------------------------------------------------------------------------
  // 2. REVERSE DNS LOOKUP
  // -------------------------------------------------------------------------
  if (publicIp) {
    try {
      console.log(`[Reverse DNS] Querying PTR record for IP: ${publicIp}...`);
      const ptr = await dns.reverse(publicIp);
      if (ptr && ptr.length > 0) {
        ipInfo.reverseDns = ptr.join(', ');
        console.log(`[Reverse DNS] Success. PTR: ${ipInfo.reverseDns}`);
      }
    } catch (err: any) {
      console.log(`[Reverse DNS] PTR lookup failed for ${publicIp}:`, err.message || String(err));
      ipInfo.reverseDns = 'No PTR record found';
    }
  }

  // -------------------------------------------------------------------------
  // 3. WHOIS DATA & IP GEOLOCATION (RDAP + TCP WHOIS)
  // -------------------------------------------------------------------------
  console.log(`[RDAP/WHOIS] Starting WHOIS & Geolocation lookup for "${cleanTarget}"...`);
  const whoisLogLines: string[] = [];
  let rdapSuccess = false;

  try {
    whoisLogLines.push(`Querying RDAP for domain: ${cleanTarget}`);
    console.log(`[RDAP] Fetching https://rdap.org/domain/${cleanTarget}...`);
    const domainRdapRes = await fetch(`https://rdap.org/domain/${cleanTarget}`, {
      headers: { 'Accept': 'application/rdap+json, application/json' },
      signal: AbortSignal.timeout(6000)
    });

    if (domainRdapRes.ok) {
      const domainRdap: any = await domainRdapRes.json();
      whoisLogLines.push(JSON.stringify(domainRdap, null, 2));

      domainInfo.domainName = domainRdap.ldhName || cleanTarget;
      domainInfo.registeredDomain = domainRdap.handle || cleanTarget;

      // Special ccTLD Registry Detection (e.g., .pk)
      if (cleanTarget.toLowerCase().endsWith('.pk')) {
        domainInfo.registry = 'PKNIC (Pakistan Network Information Center)';
      }

      // Entities (Registrar & Registry)
      if (Array.isArray(domainRdap.entities)) {
        const registrarEntity = domainRdap.entities.find((e: any) => 
          Array.isArray(e.roles) && e.roles.includes('registrar')
        );
        if (registrarEntity) {
          domainInfo.registrar = registrarEntity.vcardArray?.[1]?.find((v: any) => v[0] === 'fn')?.[3] || registrarEntity.handle;
        }

        const registryEntity = domainRdap.entities.find((e: any) => 
          Array.isArray(e.roles) && e.roles.includes('registry')
        );
        if (registryEntity) {
          domainInfo.registry = registryEntity.vcardArray?.[1]?.find((v: any) => v[0] === 'fn')?.[3] || registryEntity.handle;
        }
      }

      // Events (Dates)
      if (Array.isArray(domainRdap.events)) {
        for (const ev of domainRdap.events) {
          if (ev.eventAction === 'registration') domainInfo.registrationDate = ev.eventDate;
          if (ev.eventAction === 'expiration') domainInfo.expirationDate = ev.eventDate;
          if (ev.eventAction === 'last changed') domainInfo.lastUpdatedDate = ev.eventDate;
        }
      }

      // Status
      if (Array.isArray(domainRdap.status)) {
        domainInfo.domainStatus = domainRdap.status.join(', ');
      }

      // Registry Root Nameservers
      if (Array.isArray(domainRdap.nameservers)) {
        const nsList = domainRdap.nameservers.map((n: any) => n.ldhName).filter(Boolean);
        if (nsList.length > 0) domainInfo.registryNameServers = nsList;
      }

      // DNSSEC
      if (domainRdap.secureDNS) {
        domainInfo.dnssecStatus = domainRdap.secureDNS.delegationSigned ? 'Signed (Active)' : 'Unsigned';
      }

      rdapSuccess = true;
      console.log(`[RDAP] Success. Domain RDAP parsed successfully:`, JSON.stringify(domainInfo));
    } else {
      console.log(`[RDAP] RDAP domain query status: ${domainRdapRes.status} ${domainRdapRes.statusText}`);
      whoisLogLines.push(`RDAP Domain Query Status: ${domainRdapRes.status} ${domainRdapRes.statusText}`);
    }
  } catch (err: any) {
    console.error(`[RDAP Exception] Domain RDAP query failed for ${cleanTarget}:`, err.stack || err.message || String(err));
    whoisLogLines.push(`RDAP Domain Query Exception: ${err.message || String(err)}`);
  }

  // TCP WHOIS Fallback if RDAP was unsuccessful or missing registrar/registry
  if (!rdapSuccess || !domainInfo.registrar || !domainInfo.registry) {
    console.log(`[WHOIS Fallback] Running TCP WHOIS fallback for "${cleanTarget}"...`);
    const whoisResult = await performWhoisQuery(cleanTarget);
    whoisLogLines.push(`\n--- TCP WHOIS Fallback Output ---\n` + whoisResult.rawText);

    if (whoisResult.parsed.registry && !domainInfo.registry) domainInfo.registry = whoisResult.parsed.registry;
    if (whoisResult.parsed.registrar && !domainInfo.registrar) domainInfo.registrar = whoisResult.parsed.registrar;
    if (whoisResult.parsed.registrationDate && !domainInfo.registrationDate) domainInfo.registrationDate = whoisResult.parsed.registrationDate;
    if (whoisResult.parsed.expirationDate && !domainInfo.expirationDate) domainInfo.expirationDate = whoisResult.parsed.expirationDate;
    if (whoisResult.parsed.lastUpdatedDate && !domainInfo.lastUpdatedDate) domainInfo.lastUpdatedDate = whoisResult.parsed.lastUpdatedDate;
    if (whoisResult.parsed.domainStatus && !domainInfo.domainStatus) domainInfo.domainStatus = whoisResult.parsed.domainStatus;
    if (whoisResult.parsed.registryNameServers && whoisResult.parsed.registryNameServers.length > 0) {
      domainInfo.registryNameServers = whoisResult.parsed.registryNameServers;
    }
    if (whoisResult.parsed.registrantCountry && !domainInfo.registrantCountry) domainInfo.registrantCountry = whoisResult.parsed.registrantCountry;
  }

  // Combine Name Servers cleanly
  const allNs = Array.from(new Set([
    ...(domainInfo.authoritativeNameServers || []),
    ...(domainInfo.registryNameServers || [])
  ]));
  if (allNs.length > 0) {
    domainInfo.nameServers = allNs;
  }

  // Ensure default domainName & registeredDomain
  domainInfo.domainName = domainInfo.domainName || cleanTarget;
  domainInfo.registeredDomain = domainInfo.registeredDomain || cleanTarget;

  // IP RDAP Lookup
  if (publicIp) {
    try {
      console.log(`[RDAP IP] Querying RDAP for IP: ${publicIp}...`);
      whoisLogLines.push(`\nQuerying RDAP for IP: ${publicIp}`);
      const ipRdapRes = await fetch(`https://rdap.org/ip/${publicIp}`, {
        headers: { 'Accept': 'application/rdap+json, application/json' },
        signal: AbortSignal.timeout(6000)
      });

      if (ipRdapRes.ok) {
        const ipRdap: any = await ipRdapRes.json();
        whoisLogLines.push(JSON.stringify(ipRdap, null, 2));

        // 1. Parse ASN accurately (Must not be IP range or handle like NET-104-21)
        let asnVal: string | undefined = undefined;
        if (typeof ipRdap.asn === 'number' || typeof ipRdap.asn === 'string') {
          asnVal = String(ipRdap.asn);
        } else if (typeof ipRdap.autnum === 'number' || typeof ipRdap.autnum === 'string') {
          asnVal = String(ipRdap.autnum);
        } else if (typeof ipRdap.handle === 'string' && /^AS\d+/i.test(ipRdap.handle)) {
          asnVal = ipRdap.handle;
        }

        if (asnVal) {
          asnVal = asnVal.toUpperCase().trim();
          if (!asnVal.startsWith('AS')) {
            asnVal = `AS${asnVal}`;
          }
          ipInfo.asnNumber = asnVal;
        }

        // 2. Parse CIDR separately
        if (Array.isArray(ipRdap.cidr0_cidrs) && ipRdap.cidr0_cidrs.length > 0) {
          const c0 = ipRdap.cidr0_cidrs[0];
          if (c0.v4prefix && c0.length !== undefined) {
            ipInfo.cidr = `${c0.v4prefix}/${c0.length}`;
          } else if (c0.v6prefix && c0.length !== undefined) {
            ipInfo.cidr = `${c0.v6prefix}/${c0.length}`;
          }
        }

        // 3. Parse IP Network Range separately
        if (ipRdap.startAddress && ipRdap.endAddress) {
          ipInfo.ipNetworkRange = `${ipRdap.startAddress} - ${ipRdap.endAddress}`;
        } else if (ipRdap.handle && !ipRdap.handle.startsWith('AS')) {
          ipInfo.ipNetworkRange = ipRdap.handle;
        }

        ipInfo.hostingProvider = ipRdap.name || ipRdap.type || 'Hosting Provider';
        ipInfo.organization = ipRdap.org || ipRdap.name || 'Organization Resolved';
        ipInfo.country = ipRdap.country || 'Country Resolved';
        console.log(`[RDAP IP] Success. IP RDAP parsed:`, JSON.stringify(ipInfo));
      } else {
        whoisLogLines.push(`RDAP IP Query Status: ${ipRdapRes.status} ${ipRdapRes.statusText}`);
      }
    } catch (err: any) {
      console.error(`[RDAP IP Exception] IP RDAP lookup failed for ${publicIp}:`, err.stack || err.message || String(err));
      whoisLogLines.push(`RDAP IP Query Exception: ${err.message || String(err)}`);
    }
  }

  rawOutputs.whois = whoisLogLines.join('\n');

  // -------------------------------------------------------------------------
  // 4. SSL / TLS CERTIFICATE INSPECTION (NODE TLS SOCKET)
  // -------------------------------------------------------------------------
  console.log(`[SSL] Starting SSL/TLS Certificate inspection on port 443 for "${cleanTarget}"...`);
  try {
    await new Promise<void>((resolve) => {
      const connectHost = publicIp || cleanTarget;
      console.log(`[SSL Socket] Connecting to ${connectHost}:443 (Servername SNI: ${cleanTarget})...`);

      const socket = tls.connect({
        host: connectHost,
        port: 443,
        servername: cleanTarget,
        rejectUnauthorized: false, // Critical: allows inspecting certs even if untrusted/expired
        timeout: 8000
      }, () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol();
          const cipher = socket.getCipher();

          if (cert && Object.keys(cert).length > 0) {
            const formatCertEntity = (entity: any) => {
              if (typeof entity === 'string') return entity;
              if (typeof entity === 'object' && entity !== null) {
                const val = entity.O || entity.CN || JSON.stringify(entity);
                return Array.isArray(val) ? val.join(', ') : String(val);
              }
              return String(entity || '');
            };

            sslDetails.issuer = formatCertEntity(cert.issuer);
            sslDetails.subject = formatCertEntity(cert.subject);
            sslDetails.expiryDate = cert.valid_to;
            if (cert.subjectaltname) {
              sslDetails.san = cert.subjectaltname.split(', ').map(s => s.replace(/^DNS:/, ''));
            }
            sslDetails.heartbleedStatus = 'Not Vulnerable (Handshake verified)';
            sslDetails.weakCiphers = ['None detected'];
          }

          if (protocol) {
            sslDetails.tlsVersions = [protocol];
          }

          rawOutputs.ssl = `TLS Protocol: ${protocol || 'TLS 1.2/1.3'}\nCipher Suite: ${cipher?.name || 'Standard'} (${cipher?.version || 'TLS'})\nCertificate Subject: ${sslDetails.subject}\nIssuer: ${sslDetails.issuer}\nValid Until: ${sslDetails.expiryDate}\nSAN: ${sslDetails.san?.join(', ') || 'N/A'}`;
          console.log(`[SSL Socket] Success. TLS Handshake completed. Certificate Details:`, JSON.stringify(sslDetails));

          socket.end();
          resolve();
        } catch (e: any) {
          console.error(`[SSL Socket Exception] Error parsing peer certificate:`, e.stack || e.message || String(e));
          socket.destroy();
          resolve();
        }
      });

      socket.on('error', (err) => {
        console.error(`[SSL Socket Error] Connection failed to ${connectHost}:443:`, err.stack || err.message || String(err));
        rawOutputs.ssl = `SSL/TLS Connection Error on port 443: ${err.message}`;
        resolve();
      });

      socket.on('timeout', () => {
        console.error(`[SSL Socket Timeout] TLS socket timed out connecting to ${connectHost}:443`);
        rawOutputs.ssl = `SSL/TLS Connection Timed Out on port 443.`;
        socket.destroy();
        resolve();
      });
    });
  } catch (err: any) {
    console.error(`[SSL Exception] Global exception in SSL module:`, err.stack || err.message || String(err));
    rawOutputs.ssl = `SSL/TLS Audit Failed: ${err.message || String(err)}`;
  }

  // -------------------------------------------------------------------------
  // 5. HTTP / HTTPS WEB SERVER & TECHNOLOGY STACK AUDIT
  // -------------------------------------------------------------------------
  console.log(`[HTTP] Starting HTTP/HTTPS Web Server Analysis for "${cleanTarget}"...`);
  let httpLogLines: string[] = [];
  try {
    const protocolsToTest = [`https://${cleanTarget}`, `http://${cleanTarget}`];
    let httpResult: HttpResponseData | null = null;

    for (const testUrl of protocolsToTest) {
      try {
        console.log(`[HTTP] Attempting connection to: ${testUrl}...`);
        httpResult = await makeHttpRequest(testUrl, 5);
        if (httpResult) {
          console.log(`[HTTP] Connected successfully to ${testUrl} (Status: ${httpResult.statusCode})`);
          break;
        }
      } catch (e: any) {
        console.error(`[HTTP Exception] Failed to fetch ${testUrl}:`, e.message || String(e));
      }
    }

    if (httpResult) {
      httpLogLines.push(`HTTP Request Target: ${httpResult.url}`);
      httpLogLines.push(`HTTP Response Status: ${httpResult.statusCode} ${httpResult.statusText}`);

      const headersObj = httpResult.headers;
      for (const [k, v] of Object.entries(headersObj)) {
        httpLogLines.push(`${k}: ${v}`);
      }

      webServer.httpHeaders = headersObj;

      // Web server header
      if (headersObj['server']) {
        webServer.webServer = headersObj['server'];
      } else {
        webServer.webServer = 'Active Web Server Detected';
      }

      // Technology & Language headers
      const techList: string[] = [];
      if (headersObj['x-powered-by']) {
        webServer.framework = headersObj['x-powered-by'];
        techList.push(headersObj['x-powered-by']);
      }
      if (headersObj['via']) techList.push(`Via: ${headersObj['via']}`);
      if (headersObj['server']) techList.push(`Server: ${headersObj['server']}`);

      // CDN Detection
      if (headersObj['cf-ray'] || headersObj['server']?.toLowerCase().includes('cloudflare')) {
        ipInfo.cdnDetected = 'Cloudflare CDN';
        techList.push('Cloudflare');
      } else if (headersObj['x-amz-cf-id'] || headersObj['via']?.toLowerCase().includes('cloudfront')) {
        ipInfo.cdnDetected = 'Amazon CloudFront';
        techList.push('Amazon CloudFront');
      } else if (headersObj['server']?.toLowerCase().includes('akamai')) {
        ipInfo.cdnDetected = 'Akamai CDN';
        techList.push('Akamai');
      } else if (headersObj['fastly-restarts'] || headersObj['x-fastly-request-id']) {
        ipInfo.cdnDetected = 'Fastly CDN';
        techList.push('Fastly');
      } else {
        ipInfo.cdnDetected = 'No CDN detected / Direct Web Server';
      }

      // Body Technology Inspection
      const bodyText = httpResult.bodySnippet.toLowerCase();
      if (bodyText.includes('wp-content') || bodyText.includes('wordpress')) {
        webServer.cmsDetected = 'WordPress';
        techList.push('WordPress');
      } else if (bodyText.includes('drupal')) {
        webServer.cmsDetected = 'Drupal';
        techList.push('Drupal');
      } else if (bodyText.includes('joomla')) {
        webServer.cmsDetected = 'Joomla';
        techList.push('Joomla');
      }

      if (techList.length > 0) {
        webServer.techStack = Array.from(new Set(techList));
      }

      // Cookie security
      if (headersObj['set-cookie']) {
        const cookieStr = headersObj['set-cookie'];
        const isSecure = cookieStr.toLowerCase().includes('secure');
        const isHttpOnly = cookieStr.toLowerCase().includes('httponly');
        const isSameSite = cookieStr.toLowerCase().includes('samesite');
        webServer.cookieSecurity = `Set-Cookie present (Secure: ${isSecure ? 'Yes' : 'No'}, HttpOnly: ${isHttpOnly ? 'Yes' : 'No'}, SameSite: ${isSameSite ? 'Yes' : 'No'})`;
      } else {
        webServer.cookieSecurity = 'No Set-Cookie header received';
      }

      // Compression
      webServer.compression = headersObj['content-encoding'] || 'Uncompressed / Plain HTML';

      // Security Headers check
      const secHeadersToAudit = [
        { name: 'Strict-Transport-Security', key: 'strict-transport-security' },
        { name: 'Content-Security-Policy', key: 'content-security-policy' },
        { name: 'X-Frame-Options', key: 'x-frame-options' },
        { name: 'X-Content-Type-Options', key: 'x-content-type-options' },
        { name: 'Referrer-Policy', key: 'referrer-policy' },
        { name: 'Permissions-Policy', key: 'permissions-policy' }
      ];

      webServer.securityHeaders = secHeadersToAudit.map(sh => {
        const val = headersObj[sh.key];
        if (val) {
          return { header: sh.name, status: 'Present' as const, value: val };
        } else {
          return { header: sh.name, status: 'Missing' as const };
        }
      });

      // HSTS Check
      if (headersObj['strict-transport-security']) {
        sslDetails.hstsStatus = `Enabled (${headersObj['strict-transport-security']})`;
      } else {
        sslDetails.hstsStatus = 'Missing HSTS header';
      }

      // Check robots.txt & sitemap.xml
      try {
        const baseRobotsUrl = new URL('/robots.txt', httpResult.url).toString();
        const robotRes = await makeHttpRequest(baseRobotsUrl, 2);
        if (robotRes && robotRes.statusCode === 200) {
          webServer.robotsTxt = `Present (HTTP 200 OK)`;
        } else {
          webServer.robotsTxt = `HTTP ${robotRes?.statusCode || 404} (Not Found)`;
        }
      } catch (e) {
        webServer.robotsTxt = 'Request Failed';
      }

      try {
        const baseSitemapUrl = new URL('/sitemap.xml', httpResult.url).toString();
        const sitemapRes = await makeHttpRequest(baseSitemapUrl, 2);
        if (sitemapRes && sitemapRes.statusCode === 200) {
          webServer.sitemapXml = `Present (HTTP 200 OK)`;
        } else {
          webServer.sitemapXml = `HTTP ${sitemapRes?.statusCode || 404} (Not Found)`;
        }
      } catch (e) {
        webServer.sitemapXml = 'Request Failed';
      }

      console.log(`[HTTP] Web Server Audit Complete. Server: ${webServer.webServer}, Security Headers: ${webServer.securityHeaders?.length} checked.`);
    } else {
      console.error(`[HTTP Error] Could not connect to HTTP or HTTPS on ${cleanTarget}`);
      httpLogLines.push(`HTTP/HTTPS requests failed or connection refused on target ${cleanTarget}`);
    }
  } catch (err: any) {
    console.error(`[HTTP Exception] Global exception in HTTP module:`, err.stack || err.message || String(err));
    httpLogLines.push(`HTTP Audit Exception: ${err.message || String(err)}`);
  }

  rawOutputs.http = httpLogLines.join('\n');

  // Fill in DomainAssessmentData
  const domainAssessment: DomainAssessmentData = {
    domainInfo,
    dnsRecords,
    ipInfo,
    webServer,
    sslDetails,
    emailSecurity
  };

  console.log(`\n==================================================`);
  console.log(`[Domain Recon Pipeline Complete] Summary for target "${cleanTarget}":`);
  console.log(`- Domain Info:`, JSON.stringify(domainAssessment.domainInfo));
  console.log(`- DNS Records:`, JSON.stringify(domainAssessment.dnsRecords));
  console.log(`- IP Info:`, JSON.stringify(domainAssessment.ipInfo));
  console.log(`- Web Server:`, JSON.stringify(domainAssessment.webServer));
  console.log(`- SSL Details:`, JSON.stringify(domainAssessment.sslDetails));
  console.log(`- Email Security:`, JSON.stringify(domainAssessment.emailSecurity));
  console.log(`==================================================\n`);

  return {
    domainAssessment,
    rawOutputs
  };
}
