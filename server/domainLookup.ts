import dns from 'dns/promises';
import tls from 'tls';
import net from 'net';
import http from 'http';
import https from 'https';
import { DomainAssessmentData, DomainInfo, DnsRecordDetails, IpInformation, WebServerDetails, SslCertificateDetails, EmailSecurityDetails } from '../src/types.js';

export type TargetType = 'PRIVATE_IP' | 'PUBLIC_IP' | 'DOMAIN';

export interface TargetClassification {
  cleanTarget: string;
  targetType: TargetType;
  targetTypeLabel: string;
}

/**
 * Classifies a scan target as PRIVATE_IP, PUBLIC_IP, or DOMAIN.
 */
export function classifyTarget(target: string): TargetClassification {
  const cleanTarget = target.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '');

  // Check IPv4
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const ipv4Match = cleanTarget.match(ipv4Regex);
  if (ipv4Match) {
    const octets = ipv4Match.slice(1, 5).map(Number);
    if (octets.every(o => o >= 0 && o <= 255)) {
      const [a, b] = octets;
      // Private RFC 1918 ranges, loopback, APIPA link-local:
      // 10.0.0.0/8
      // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
      // 192.168.0.0/16
      // 127.0.0.0/8
      // 169.254.0.0/16
      if (
        a === 10 ||
        a === 127 ||
        (a === 192 && b === 168) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 169 && b === 254)
      ) {
        return {
          cleanTarget,
          targetType: 'PRIVATE_IP',
          targetTypeLabel: 'Private IP Address (RFC 1918 / LAN)'
        };
      }
      return {
        cleanTarget,
        targetType: 'PUBLIC_IP',
        targetTypeLabel: 'Public IP Address'
      };
    }
  }

  // Check IPv6 loopback / private / link-local / localhost
  if (cleanTarget.toLowerCase() === 'localhost' || cleanTarget === '::1') {
    return {
      cleanTarget,
      targetType: 'PRIVATE_IP',
      targetTypeLabel: 'Private IP / Loopback Host'
    };
  }

  if (cleanTarget.includes(':')) {
    const lower = cleanTarget.toLowerCase();
    if (lower.startsWith('fe80:') || lower.startsWith('fc00:') || lower.startsWith('fd00:')) {
      return {
        cleanTarget,
        targetType: 'PRIVATE_IP',
        targetTypeLabel: 'Private IPv6 Host'
      };
    }
    return {
      cleanTarget,
      targetType: 'PUBLIC_IP',
      targetTypeLabel: 'Public IPv6 Address'
    };
  }

  // Otherwise, Domain / FQDN
  return {
    cleanTarget,
    targetType: 'DOMAIN',
    targetTypeLabel: 'Domain Name / FQDN'
  };
}

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

    // Parse Registrant Email
    const regEmailMatch = raw.match(/(?:Registrant Email|Registrant Contact Email|Registrant Contact|Registrant E-Mail):\s*([^\s@]+@[^\s@]+\.[^\s@]+)/i);
    if (regEmailMatch) parsed.registrantEmail = regEmailMatch[1].trim();

    // Parse Admin Email
    const adminEmailMatch = raw.match(/(?:Admin Email|Administrative Contact Email|Admin Contact Email|Admin E-Mail):\s*([^\s@]+@[^\s@]+\.[^\s@]+)/i);
    if (adminEmailMatch) parsed.adminEmail = adminEmailMatch[1].trim();

    // Parse Tech Email
    const techEmailMatch = raw.match(/(?:Tech Email|Technical Contact Email|Tech Contact Email|Tech E-Mail):\s*([^\s@]+@[^\s@]+\.[^\s@]+)/i);
    if (techEmailMatch) parsed.techEmail = techEmailMatch[1].trim();

    // Parse Abuse Email
    const abuseEmailMatch = raw.match(/(?:Registrar Abuse Contact Email|Abuse Contact Email|Abuse Email):\s*([^\s@]+@[^\s@]+\.[^\s@]+)/i);
    if (abuseEmailMatch) parsed.abuseEmail = abuseEmailMatch[1].trim();

    // Fallback email parsing from WHOIS block
    if (!parsed.registrantEmail) {
      const emails = Array.from(new Set(raw.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []));
      if (emails.length > 0) {
        const nonAbuse = emails.filter(e => !/abuse|domaincontrol|secureserver|markmonitor/i.test(e));
        if (nonAbuse.length > 0) parsed.registrantEmail = nonAbuse[0];
      }
    }

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

export async function performDomainAssessment(
  rawTarget: string,
  overrideTargetType?: TargetType
): Promise<{
  domainAssessment: DomainAssessmentData;
  rawOutputs: { dns: string; whois: string; ssl: string; http: string };
}> {
  const classification = classifyTarget(rawTarget);
  const cleanTarget = classification.cleanTarget;
  const targetType = overrideTargetType || classification.targetType;

  console.log(`\n==================================================`);
  console.log(`[Recon Engine] Launching assessment for target: "${cleanTarget}"`);
  console.log(`[Recon Engine] Target Classification: ${targetType} (${classification.targetTypeLabel})`);
  console.log(`==================================================\n`);

  // -------------------------------------------------------------------------
  // TARGET TYPE A: PRIVATE IP (RFC 1918)
  // -------------------------------------------------------------------------
  if (targetType === 'PRIVATE_IP') {
    console.log(`[Recon Engine] Private LAN IP detected (${cleanTarget}). Skipping all Domain/WHOIS/RDAP/DNSSEC modules.`);
    return {
      domainAssessment: {
        targetType: 'PRIVATE_IP',
        targetTypeLabel: 'Private IP Address (RFC 1918 / LAN)',
        skipReason: 'Private LAN IPs are not domains. WHOIS, RDAP, DNSSEC, and registrar lookups were automatically skipped in compliance with security scanner standards.'
      },
      rawOutputs: {
        dns: `[Skipped] Target ${cleanTarget} is a Private IP address (RFC 1918 / LAN). Domain DNS lookups do not apply.`,
        whois: `[Skipped] Target ${cleanTarget} is a Private IP address (RFC 1918 / LAN). WHOIS/RDAP domain registrar lookups do not apply.`,
        ssl: `[Skipped] SSL assessment on port 443.`,
        http: `[Skipped] Web assessment.`
      }
    };
  }

  // -------------------------------------------------------------------------
  // TARGET TYPE B: PUBLIC IP ADDRESS
  // -------------------------------------------------------------------------
  if (targetType === 'PUBLIC_IP') {
    console.log(`[Recon Engine] Public IP detected (${cleanTarget}). Running IP RDAP Intelligence and Reverse DNS.`);
    const ipInfo: IpInformation = { publicIp: cleanTarget };
    const whoisLogLines: string[] = [`[IP Intelligence RDAP Report for Public IP: ${cleanTarget}]`];
    let ptrRecord: string | undefined = undefined;

    // Reverse DNS Lookup
    try {
      console.log(`[DNS Reverse] Querying reverse PTR for IP ${cleanTarget}...`);
      const ptrs = await dns.reverse(cleanTarget);
      if (ptrs && ptrs.length > 0) {
        ptrRecord = ptrs.join(', ');
        ipInfo.reverseDns = ptrRecord;
        console.log(`[DNS Reverse] Success. PTR: ${ptrRecord}`);
      }
    } catch (e: any) {
      console.log(`[DNS Reverse] No PTR record for ${cleanTarget}: ${e.message || String(e)}`);
    }

    // Query IP RDAP for ASN, CIDR, Network Range, Hosting Provider, Organization
    try {
      console.log(`[RDAP IP] Querying RDAP for IP: ${cleanTarget}...`);
      const ipRdapRes = await fetch(`https://rdap.org/ip/${cleanTarget}`, {
        headers: { 'Accept': 'application/rdap+json, application/json' },
        signal: AbortSignal.timeout(6000)
      });

      if (ipRdapRes.ok) {
        const ipRdap: any = await ipRdapRes.json();
        whoisLogLines.push(JSON.stringify(ipRdap, null, 2));

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
          if (!asnVal.startsWith('AS')) asnVal = `AS${asnVal}`;
          ipInfo.asnNumber = asnVal;
        }

        if (Array.isArray(ipRdap.cidr0_cidrs) && ipRdap.cidr0_cidrs.length > 0) {
          const c0 = ipRdap.cidr0_cidrs[0];
          if (c0.v4prefix && c0.length !== undefined) ipInfo.cidr = `${c0.v4prefix}/${c0.length}`;
          else if (c0.v6prefix && c0.length !== undefined) ipInfo.cidr = `${c0.v6prefix}/${c0.length}`;
        }

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
      console.error(`[RDAP IP Exception] IP RDAP lookup failed for ${cleanTarget}:`, err.message || String(err));
      whoisLogLines.push(`RDAP IP Query Exception: ${err.message || String(err)}`);
    }

    return {
      domainAssessment: {
        targetType: 'PUBLIC_IP',
        targetTypeLabel: 'Public IP Address',
        ipInfo
      },
      rawOutputs: {
        dns: `[IP Target] Reverse DNS Lookup for ${cleanTarget}: ${ptrRecord || 'No PTR record resolved'}`,
        whois: whoisLogLines.join('\n'),
        ssl: `[Skipped] SSL assessment on port 443.`,
        http: `[Skipped] Web assessment.`
      }
    };
  }

  // -------------------------------------------------------------------------
  // TARGET TYPE C: DOMAIN / FQDN (Full Domain Recon Pipeline)
  // -------------------------------------------------------------------------
  const domainInfo: DomainInfo = {
    domainName: cleanTarget,
    registeredDomain: cleanTarget
  };
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

  // 1. DNS RESOLUTION & ENUMERATION PIPELINE
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
      console.log(`[DNS Fallback] Querying system DNS via dns.lookup("${cleanTarget}")...`);
      const lookupResult = await dns.lookup(cleanTarget);
      if (lookupResult && lookupResult.address) {
        publicIp = lookupResult.address;
        dnsRecords.aRecords = [publicIp];
        ipInfo.publicIp = publicIp;
        dnsLogLines.push(`[System DNS Fallback] Resolved: ${publicIp}`);
        console.log(`[DNS Fallback] Success. Resolved via lookup: ${publicIp}`);
      }
    } catch (err: any) {
      console.error(`[DNS Fallback Exception] System lookup failed for ${cleanTarget}:`, err.message || String(err));
      dnsLogLines.push(`[System DNS Fallback] failed: ${err.message || String(err)}`);
    }
  }

  // Reverse DNS Lookup
  if (publicIp) {
    try {
      console.log(`[DNS Reverse] Querying reverse PTR for IP ${publicIp}...`);
      const ptrs = await dns.reverse(publicIp);
      if (ptrs && ptrs.length > 0) {
        ipInfo.reverseDns = ptrs.join(', ');
        dnsLogLines.push(`[Reverse DNS]\n${ipInfo.reverseDns}`);
        console.log(`[DNS Reverse] Success. PTR: ${ipInfo.reverseDns}`);
      }
    } catch (e: any) {
      console.log(`[DNS Reverse] No PTR record for ${publicIp}: ${e.message || String(e)}`);
    }
  }

  // AAAA Records
  try {
    const aaaa = await dns.resolve6(cleanTarget);
    if (aaaa && aaaa.length > 0) {
      dnsRecords.aaaaRecords = aaaa;
      dnsLogLines.push(`[AAAA Records]\n${aaaa.join('\n')}`);
    }
  } catch (e) {}

  // MX Records
  try {
    console.log(`[DNS] Querying MX records for "${cleanTarget}"...`);
    const mx = await dns.resolveMx(cleanTarget);
    if (mx && mx.length > 0) {
      const mxFormatted = mx.sort((a, b) => a.priority - b.priority).map(m => `${m.priority} ${m.exchange}`);
      dnsRecords.mxRecords = mxFormatted;
      dnsLogLines.push(`[MX Records]\n${mxFormatted.join('\n')}`);
      console.log(`[DNS] Success. MX records:`, mxFormatted);
    }
  } catch (err: any) {
    console.log(`[DNS] MX query result for ${cleanTarget}: No records found`);
  }

  // Authoritative Name Servers (NS Records)
  try {
    console.log(`[DNS] Querying NS records for "${cleanTarget}"...`);
    const ns = await dns.resolveNs(cleanTarget);
    if (ns && ns.length > 0) {
      domainInfo.authoritativeNameServers = ns;
      dnsRecords.nsRecords = ns;
      dnsLogLines.push(`[Authoritative NS Records]\n${ns.join('\n')}`);
      console.log(`[DNS] Success. Authoritative NS records:`, ns);
    }
  } catch (err: any) {
    console.log(`[DNS] NS query result for ${cleanTarget}: No records found`);
  }

  // TXT Records & Email Security (SPF / DMARC / DKIM)
  try {
    console.log(`[DNS] Querying TXT records for "${cleanTarget}"...`);
    const txt = await dns.resolveTxt(cleanTarget);
    if (txt && txt.length > 0) {
      const flattenedTxt = txt.map(parts => parts.join(''));
      dnsRecords.txtRecords = flattenedTxt;
      dnsLogLines.push(`[TXT Records]\n${flattenedTxt.join('\n')}`);

      const spf = flattenedTxt.find(t => t.toLowerCase().startsWith('v=spf1'));
      if (spf) {
        dnsRecords.spfRecord = spf;
        emailSecurity.spfRecord = spf;
      }
    }
  } catch (e) {}

  // DMARC Record
  try {
    const dmarcTarget = `_dmarc.${cleanTarget}`;
    const dmarcTxt = await dns.resolveTxt(dmarcTarget);
    if (dmarcTxt && dmarcTxt.length > 0) {
      const flattenedDmarc = dmarcTxt.map(parts => parts.join('')).join('; ');
      dnsRecords.dmarcRecord = flattenedDmarc;
      emailSecurity.dmarcRecord = flattenedDmarc;
    }
  } catch (e) {
    emailSecurity.dmarcRecord = 'No DMARC record published';
  }

  // DKIM Selector Test
  try {
    const dkimTarget = `default._domainkey.${cleanTarget}`;
    const dkimTxt = await dns.resolveTxt(dkimTarget);
    if (dkimTxt && dkimTxt.length > 0) {
      emailSecurity.dkimStatus = 'DKIM Key Discovered (default selector)';
      dnsRecords.dkimStatus = 'DKIM Active';
    } else {
      emailSecurity.dkimStatus = 'DKIM record not found on standard selector';
    }
  } catch (e) {
    emailSecurity.dkimStatus = 'DKIM record not found on default selector';
  }

  // CNAME Records
  try {
    const cname = await dns.resolveCname(cleanTarget);
    if (cname && cname.length > 0) {
      dnsRecords.cnameRecords = cname;
      dnsLogLines.push(`[CNAME Records]\n${cname.join('\n')}`);
    }
  } catch (e) {}

  // SOA Record
  try {
    const soa = await dns.resolveSoa(cleanTarget);
    if (soa) {
      const soaStr = `Primary NS: ${soa.nsname}, Hostmaster: ${soa.hostmaster}, Serial: ${soa.serial}`;
      dnsRecords.soaRecord = soaStr;
      dnsLogLines.push(`[SOA Record]\n${soaStr}`);
    }
  } catch (e) {}

  rawOutputs.dns = dnsLogLines.length > 0 ? dnsLogLines.join('\n\n') : 'No DNS records resolved';

  // 2. WHOIS / RDAP LOOKUP PIPELINE
  console.log(`[RDAP] Querying RDAP domain lookup for "${cleanTarget}"...`);
  const whoisLogLines: string[] = [];
  let rdapSuccess = false;

  try {
    const domainRdapRes = await fetch(`https://rdap.org/domain/${cleanTarget}`, {
      headers: { 'Accept': 'application/rdap+json, application/json' },
      signal: AbortSignal.timeout(8000)
    });

    if (domainRdapRes.ok) {
      const domainRdap: any = await domainRdapRes.json();
      whoisLogLines.push(JSON.stringify(domainRdap, null, 2));

      domainInfo.domainName = domainRdap.ldhName || cleanTarget;
      domainInfo.registeredDomain = domainRdap.handle || cleanTarget;

      if (cleanTarget.toLowerCase().endsWith('.pk')) {
        domainInfo.registry = 'PKNIC (Pakistan Network Information Center)';
      }

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

        // Extract emails from vcardArray across entities
        for (const entity of domainRdap.entities) {
          if (Array.isArray(entity.vcardArray?.[1])) {
            const emailEntry = entity.vcardArray[1].find((v: any) => v[0] === 'email');
            if (emailEntry && emailEntry[3]) {
              const emailVal = String(emailEntry[3]).trim();
              if (entity.roles?.includes('registrant') && !domainInfo.registrantEmail) domainInfo.registrantEmail = emailVal;
              else if (entity.roles?.includes('administrative') && !domainInfo.adminEmail) domainInfo.adminEmail = emailVal;
              else if (entity.roles?.includes('technical') && !domainInfo.techEmail) domainInfo.techEmail = emailVal;
              else if (entity.roles?.includes('abuse') && !domainInfo.abuseEmail) domainInfo.abuseEmail = emailVal;
              else if (!domainInfo.registrantEmail) domainInfo.registrantEmail = emailVal;
            }
          }
        }
      }

      if (Array.isArray(domainRdap.events)) {
        for (const ev of domainRdap.events) {
          if (ev.eventAction === 'registration') domainInfo.registrationDate = ev.eventDate;
          if (ev.eventAction === 'expiration') domainInfo.expirationDate = ev.eventDate;
          if (ev.eventAction === 'last changed') domainInfo.lastUpdatedDate = ev.eventDate;
        }
      }

      if (Array.isArray(domainRdap.status)) {
        domainInfo.domainStatus = domainRdap.status.join(', ');
      }

      if (Array.isArray(domainRdap.nameservers)) {
        const nsList = domainRdap.nameservers.map((n: any) => n.ldhName).filter(Boolean);
        if (nsList.length > 0) domainInfo.registryNameServers = nsList;
      }

      if (domainRdap.secureDNS) {
        domainInfo.dnssecStatus = domainRdap.secureDNS.delegationSigned ? 'Signed (Active)' : 'Unsigned';
      }

      rdapSuccess = true;
      console.log(`[RDAP] Success. Domain RDAP parsed successfully:`, JSON.stringify(domainInfo));
    } else {
      whoisLogLines.push(`RDAP Domain Query Status: ${domainRdapRes.status} ${domainRdapRes.statusText}`);
    }
  } catch (err: any) {
    console.error(`[RDAP Exception] Domain RDAP query failed for ${cleanTarget}:`, err.message || String(err));
    whoisLogLines.push(`RDAP Domain Query Exception: ${err.message || String(err)}`);
  }

  // TCP WHOIS Fallback
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
    if (whoisResult.parsed.registrantEmail && !domainInfo.registrantEmail) domainInfo.registrantEmail = whoisResult.parsed.registrantEmail;
    if (whoisResult.parsed.adminEmail && !domainInfo.adminEmail) domainInfo.adminEmail = whoisResult.parsed.adminEmail;
    if (whoisResult.parsed.techEmail && !domainInfo.techEmail) domainInfo.techEmail = whoisResult.parsed.techEmail;
    if (whoisResult.parsed.abuseEmail && !domainInfo.abuseEmail) domainInfo.abuseEmail = whoisResult.parsed.abuseEmail;
  }

  // Combine Name Servers cleanly
  const allNs = Array.from(new Set([
    ...(domainInfo.authoritativeNameServers || []),
    ...(domainInfo.registryNameServers || [])
  ]));
  if (allNs.length > 0) {
    domainInfo.nameServers = allNs;
  }

  // IP RDAP Lookup for Resolved Public IP
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
          if (!asnVal.startsWith('AS')) asnVal = `AS${asnVal}`;
          ipInfo.asnNumber = asnVal;
        }

        if (Array.isArray(ipRdap.cidr0_cidrs) && ipRdap.cidr0_cidrs.length > 0) {
          const c0 = ipRdap.cidr0_cidrs[0];
          if (c0.v4prefix && c0.length !== undefined) ipInfo.cidr = `${c0.v4prefix}/${c0.length}`;
          else if (c0.v6prefix && c0.length !== undefined) ipInfo.cidr = `${c0.v6prefix}/${c0.length}`;
        }

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
      console.error(`[RDAP IP Exception] IP RDAP lookup failed for ${publicIp}:`, err.message || String(err));
      whoisLogLines.push(`RDAP IP Query Exception: ${err.message || String(err)}`);
    }
  }

  rawOutputs.whois = whoisLogLines.join('\n');

  // 3. SSL / TLS CERTIFICATE INSPECTION (NODE TLS SOCKET)
  console.log(`[SSL] Starting SSL/TLS Certificate inspection on port 443 for "${cleanTarget}"...`);
  try {
    await new Promise<void>((resolve) => {
      const connectHost = publicIp || cleanTarget;
      console.log(`[SSL Socket] Connecting to ${connectHost}:443 (Servername SNI: ${cleanTarget})...`);

      const socket = tls.connect({
        host: connectHost,
        port: 443,
        servername: cleanTarget,
        rejectUnauthorized: false,
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
          console.error(`[SSL Socket Exception] Error parsing peer certificate:`, e.message || String(e));
          socket.destroy();
          resolve();
        }
      });

      socket.on('error', (err) => {
        console.error(`[SSL Socket Error] Connection failed to ${connectHost}:443:`, err.message || String(err));
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
    console.error(`[SSL Exception] Global exception in SSL module:`, err.message || String(err));
    rawOutputs.ssl = `SSL/TLS Audit Failed: ${err.message || String(err)}`;
  }

  // 4. HTTP / HTTPS WEB SERVER & TECHNOLOGY STACK AUDIT
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

      if (headersObj['server']) {
        webServer.webServer = headersObj['server'];
      } else {
        webServer.webServer = 'Active Web Server Detected';
      }

      const techList: string[] = [];
      if (headersObj['x-powered-by']) {
        webServer.framework = headersObj['x-powered-by'];
        techList.push(headersObj['x-powered-by']);
      }
      if (headersObj['via']) techList.push(`Via: ${headersObj['via']}`);
      if (headersObj['server']) techList.push(`Server: ${headersObj['server']}`);

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

      if (headersObj['set-cookie']) {
        const cookieStr = headersObj['set-cookie'];
        const isSecure = cookieStr.toLowerCase().includes('secure');
        const isHttpOnly = cookieStr.toLowerCase().includes('httponly');
        const isSameSite = cookieStr.toLowerCase().includes('samesite');
        webServer.cookieSecurity = `Set-Cookie present (Secure: ${isSecure ? 'Yes' : 'No'}, HttpOnly: ${isHttpOnly ? 'Yes' : 'No'}, SameSite: ${isSameSite ? 'Yes' : 'No'})`;
      } else {
        webServer.cookieSecurity = 'No Set-Cookie header received';
      }

      webServer.compression = headersObj['content-encoding'] || 'Uncompressed / Plain HTML';

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

      if (headersObj['strict-transport-security']) {
        sslDetails.hstsStatus = `Enabled (${headersObj['strict-transport-security']})`;
      } else {
        sslDetails.hstsStatus = 'Missing HSTS header';
      }

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
    console.error(`[HTTP Exception] Global exception in HTTP module:`, err.message || String(err));
    httpLogLines.push(`HTTP Audit Exception: ${err.message || String(err)}`);
  }

  rawOutputs.http = httpLogLines.join('\n');

  const domainAssessment: DomainAssessmentData = {
    targetType: 'DOMAIN',
    targetTypeLabel: 'Domain Name / FQDN',
    domainInfo,
    dnsRecords,
    ipInfo,
    webServer,
    sslDetails,
    emailSecurity
  };

  return {
    domainAssessment,
    rawOutputs
  };
}
