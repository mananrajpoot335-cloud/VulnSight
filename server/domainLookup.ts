import dns from 'dns/promises';
import tls from 'tls';
import { DomainAssessmentData, DomainInfo, DnsRecordDetails, IpInformation, WebServerDetails, SslCertificateDetails, EmailSecurityDetails } from '../src/types.js';

export async function performDomainAssessment(cleanTarget: string): Promise<{
  domainAssessment: DomainAssessmentData;
  rawOutputs: { dns: string; whois: string; ssl: string; http: string };
}> {
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

  // 1. REAL DNS LOOKUPS
  let dnsLogLines: string[] = [];
  let publicIp: string | undefined = undefined;

  // A Records
  try {
    const a = await dns.resolve4(cleanTarget);
    if (a && a.length > 0) {
      dnsRecords.aRecords = a;
      publicIp = a[0];
      ipInfo.publicIp = publicIp;
      dnsLogLines.push(`[A Records]\n${a.join('\n')}`);
    }
  } catch (err: any) {
    dnsLogLines.push(`[A Records] Lookup failed/none: ${err.message || String(err)}`);
  }

  // AAAA Records
  try {
    const aaaa = await dns.resolve6(cleanTarget);
    if (aaaa && aaaa.length > 0) {
      dnsRecords.aaaaRecords = aaaa;
      dnsLogLines.push(`[AAAA Records]\n${aaaa.join('\n')}`);
    }
  } catch (err: any) {
    dnsLogLines.push(`[AAAA Records] Lookup failed/none: ${err.message || String(err)}`);
  }

  // MX Records
  try {
    const mx = await dns.resolveMx(cleanTarget);
    if (mx && mx.length > 0) {
      dnsRecords.mxRecords = mx.map(m => `Priority ${m.priority}: ${m.exchange}`);
      dnsLogLines.push(`[MX Records]\n${dnsRecords.mxRecords.join('\n')}`);
      emailSecurity.mxValidation = `${mx.length} MX record(s) resolved successfully`;
    } else {
      emailSecurity.mxValidation = 'No MX records found';
    }
  } catch (err: any) {
    dnsLogLines.push(`[MX Records] Lookup failed/none: ${err.message || String(err)}`);
    emailSecurity.mxValidation = 'MX lookup failed';
  }

  // NS Records
  try {
    const ns = await dns.resolveNs(cleanTarget);
    if (ns && ns.length > 0) {
      dnsRecords.nsRecords = ns;
      domainInfo.nameServers = ns;
      dnsLogLines.push(`[NS Records]\n${ns.join('\n')}`);
    }
  } catch (err: any) {
    dnsLogLines.push(`[NS Records] Lookup failed/none: ${err.message || String(err)}`);
  }

  // CNAME Records
  try {
    const cname = await dns.resolveCname(cleanTarget);
    if (cname && cname.length > 0) {
      dnsRecords.cnameRecords = cname;
      dnsLogLines.push(`[CNAME Records]\n${cname.join('\n')}`);
    }
  } catch (err: any) {
    dnsLogLines.push(`[CNAME Records] Lookup failed/none: ${err.message || String(err)}`);
  }

  // SOA Record
  try {
    const soa = await dns.resolveSoa(cleanTarget);
    if (soa) {
      dnsRecords.soaRecord = `Hostmaster: ${soa.hostmaster}, NS: ${soa.nsname}, Serial: ${soa.serial}, Refresh: ${soa.refresh}`;
      dnsLogLines.push(`[SOA Record]\n${dnsRecords.soaRecord}`);
    }
  } catch (err: any) {
    dnsLogLines.push(`[SOA Record] Lookup failed/none: ${err.message || String(err)}`);
  }

  // TXT Records (SPF / DKIM / DMARC)
  try {
    const txt = await dns.resolveTxt(cleanTarget);
    if (txt && txt.length > 0) {
      const flattenedTxt = txt.map(t => t.join(''));
      dnsRecords.txtRecords = flattenedTxt;
      dnsLogLines.push(`[TXT Records]\n${flattenedTxt.join('\n')}`);

      const spf = flattenedTxt.find(t => t.toLowerCase().startsWith('v=spf1'));
      if (spf) {
        dnsRecords.spfRecord = spf;
        emailSecurity.spfRecord = spf;
      }
    }
  } catch (err: any) {
    dnsLogLines.push(`[TXT Records] Lookup failed/none: ${err.message || String(err)}`);
  }

  // DMARC Lookup (_dmarc.target)
  try {
    const dmarcTxt = await dns.resolveTxt(`_dmarc.${cleanTarget}`);
    if (dmarcTxt && dmarcTxt.length > 0) {
      const flattenedDmarc = dmarcTxt.map(t => t.join('')).find(t => t.toLowerCase().startsWith('v=dmarc1'));
      if (flattenedDmarc) {
        dnsRecords.dmarcRecord = flattenedDmarc;
        emailSecurity.dmarcRecord = flattenedDmarc;
        dnsLogLines.push(`[DMARC Record]\n${flattenedDmarc}`);
      }
    }
  } catch (err: any) {
    dnsLogLines.push(`[DMARC Record] Lookup failed/none: ${err.message || String(err)}`);
  }

  // DKIM Lookup (_domainkey or common selectors)
  try {
    const dkimTxt = await dns.resolveTxt(`default._domainkey.${cleanTarget}`);
    if (dkimTxt && dkimTxt.length > 0) {
      const dkimStr = dkimTxt.map(t => t.join('')).join(' ');
      dnsRecords.dkimStatus = `Detected (default selector): ${dkimStr.slice(0, 50)}...`;
      emailSecurity.dkimStatus = dnsRecords.dkimStatus;
      dnsLogLines.push(`[DKIM Record]\n${dkimStr}`);
    } else {
      dnsRecords.dkimStatus = 'Default selector not published (custom selector required)';
      emailSecurity.dkimStatus = dnsRecords.dkimStatus;
    }
  } catch (err: any) {
    dnsRecords.dkimStatus = 'Selector default._domainkey not found';
    emailSecurity.dkimStatus = dnsRecords.dkimStatus;
  }

  rawOutputs.dns = dnsLogLines.join('\n\n');

  // 2. REVERSE DNS LOOKUP
  if (publicIp) {
    try {
      const ptr = await dns.reverse(publicIp);
      if (ptr && ptr.length > 0) {
        ipInfo.reverseDns = ptr.join(', ');
      }
    } catch (err: any) {
      // Not Available
    }
  }

  // 3. WHOIS DATA & IP GEOLOCATION VIA RDAP (RFC 7480)
  let whoisLogLines: string[] = [];
  try {
    whoisLogLines.push(`Querying RDAP for domain: ${cleanTarget}`);
    const domainRdapRes = await fetch(`https://rdap.org/domain/${cleanTarget}`, {
      headers: { 'Accept': 'application/rdap+json, application/json' },
      signal: AbortSignal.timeout(6000)
    });

    if (domainRdapRes.ok) {
      const domainRdap: any = await domainRdapRes.json();
      whoisLogLines.push(JSON.stringify(domainRdap, null, 2));

      domainInfo.domainName = domainRdap.ldhName || cleanTarget;
      domainInfo.registeredDomain = domainRdap.handle || cleanTarget;

      // Entities (Registrar)
      if (Array.isArray(domainRdap.entities)) {
        const registrarEntity = domainRdap.entities.find((e: any) => 
          Array.isArray(e.roles) && e.roles.includes('registrar')
        );
        if (registrarEntity) {
          domainInfo.registrar = registrarEntity.vcardArray?.[1]?.find((v: any) => v[0] === 'fn')?.[3] || registrarEntity.handle;
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

      // Nameservers
      if (Array.isArray(domainRdap.nameservers)) {
        const nsList = domainRdap.nameservers.map((n: any) => n.ldhName).filter(Boolean);
        if (nsList.length > 0) domainInfo.nameServers = nsList;
      }

      // DNSSEC
      if (domainRdap.secureDNS) {
        domainInfo.dnssecStatus = domainRdap.secureDNS.delegationSigned ? 'Signed (Active)' : 'Unsigned';
      }
    } else {
      whoisLogLines.push(`RDAP Domain Query Status: ${domainRdapRes.status} ${domainRdapRes.statusText}`);
    }
  } catch (err: any) {
    whoisLogLines.push(`RDAP Domain Query Exception: ${err.message || String(err)}`);
  }

  // IP RDAP Lookup
  if (publicIp) {
    try {
      whoisLogLines.push(`\nQuerying RDAP for IP: ${publicIp}`);
      const ipRdapRes = await fetch(`https://rdap.org/ip/${publicIp}`, {
        headers: { 'Accept': 'application/rdap+json, application/json' },
        signal: AbortSignal.timeout(6000)
      });

      if (ipRdapRes.ok) {
        const ipRdap: any = await ipRdapRes.json();
        whoisLogLines.push(JSON.stringify(ipRdap, null, 2));

        ipInfo.asnNumber = ipRdap.asn || ipRdap.handle;
        ipInfo.hostingProvider = ipRdap.name || ipRdap.type;
        ipInfo.organization = ipRdap.org || ipRdap.name;
        ipInfo.country = ipRdap.country;
      } else {
        whoisLogLines.push(`RDAP IP Query Status: ${ipRdapRes.status} ${ipRdapRes.statusText}`);
      }
    } catch (err: any) {
      whoisLogLines.push(`RDAP IP Query Exception: ${err.message || String(err)}`);
    }
  }

  rawOutputs.whois = whoisLogLines.join('\n');

  // 4. REAL SSL / TLS AUDIT VIA NODE TLS SOCKET
  try {
    await new Promise<void>((resolve) => {
      const socket = tls.connect({
        host: cleanTarget,
        port: 443,
        servername: cleanTarget,
        rejectUnauthorized: false, // Allows inspecting certificate even if untrusted/expired
        timeout: 5000
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
          }

          if (protocol) {
            sslDetails.tlsVersions = [protocol];
          }

          if (cipher) {
            rawOutputs.ssl = `TLS Protocol: ${protocol}\nCipher Suite: ${cipher.name} (${cipher.version})\nCertificate Subject: ${sslDetails.subject}\nIssuer: ${sslDetails.issuer}\nValid Until: ${sslDetails.expiryDate}\nSAN: ${sslDetails.san?.join(', ')}`;
          } else {
            rawOutputs.ssl = `Connected to ${cleanTarget}:443 over TLS. Certificate details retrieved successfully.`;
          }

          socket.end();
          resolve();
        } catch (e) {
          socket.destroy();
          resolve();
        }
      });

      socket.on('error', (err) => {
        rawOutputs.ssl = `SSL/TLS Connection Error on port 443: ${err.message}`;
        resolve();
      });

      socket.on('timeout', () => {
        rawOutputs.ssl = `SSL/TLS Connection Timed Out on port 443.`;
        socket.destroy();
        resolve();
      });
    });
  } catch (err: any) {
    rawOutputs.ssl = `SSL/TLS Audit Failed: ${err.message || String(err)}`;
  }

  // 5. REAL HTTP / HTTPS WEB SERVER AUDIT & SECURITY HEADERS
  let httpLogLines: string[] = [];
  try {
    const protocolsToTest = ['https', 'http'];
    let resp: Response | null = null;
    let targetUrlUsed = '';

    for (const proto of protocolsToTest) {
      try {
        const testUrl = `${proto}://${cleanTarget}`;
        const res = await fetch(testUrl, {
          method: 'GET',
          redirect: 'follow',
          signal: AbortSignal.timeout(5000),
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) VulnSight-Security-Scanner/2.0'
          }
        });
        resp = res;
        targetUrlUsed = testUrl;
        break;
      } catch (e) {
        // Continue to next protocol
      }
    }

    if (resp) {
      httpLogLines.push(`HTTP Request Target: ${targetUrlUsed}`);
      httpLogLines.push(`HTTP Response Status: ${resp.status} ${resp.statusText}`);
      
      const headersObj: Record<string, string> = {};
      resp.headers.forEach((value, key) => {
        headersObj[key] = value;
        httpLogLines.push(`${key}: ${value}`);
      });

      webServer.httpHeaders = headersObj;

      // Web server header
      if (headersObj['server']) {
        webServer.webServer = headersObj['server'];
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
        ipInfo.cdnDetected = 'No CDN detected / Direct Server';
      }

      if (techList.length > 0) {
        webServer.techStack = techList;
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
      webServer.compression = headersObj['content-encoding'] || 'Uncompressed / Plain';

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

      // Check HSTS status for SSL
      if (headersObj['strict-transport-security']) {
        sslDetails.hstsStatus = `Enabled (${headersObj['strict-transport-security']})`;
      } else {
        sslDetails.hstsStatus = 'Missing HSTS header';
      }

      // Try fetching robots.txt & sitemap.xml
      try {
        const robotRes = await fetch(`${targetUrlUsed.replace(/\/$/, '')}/robots.txt`, { signal: AbortSignal.timeout(3000) });
        if (robotRes.ok) {
          webServer.robotsTxt = `Present (HTTP ${robotRes.status})`;
        } else {
          webServer.robotsTxt = `HTTP ${robotRes.status} (Not Found)`;
        }
      } catch (e) {
        webServer.robotsTxt = 'Request Failed';
      }

      try {
        const sitemapRes = await fetch(`${targetUrlUsed.replace(/\/$/, '')}/sitemap.xml`, { signal: AbortSignal.timeout(3000) });
        if (sitemapRes.ok) {
          webServer.sitemapXml = `Present (HTTP ${sitemapRes.status})`;
        } else {
          webServer.sitemapXml = `HTTP ${sitemapRes.status} (Not Found)`;
        }
      } catch (e) {
        webServer.sitemapXml = 'Request Failed';
      }

    } else {
      httpLogLines.push(`HTTP/HTTPS requests failed or connection refused on target ${cleanTarget}`);
    }
  } catch (err: any) {
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

  return {
    domainAssessment,
    rawOutputs
  };
}
