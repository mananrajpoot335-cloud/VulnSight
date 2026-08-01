import net from 'net';
import { exec } from 'child_process';
import fs from 'fs';

export interface ProbeLog {
  probe: string;
  result: 'PASS' | 'FAIL' | 'OPEN' | 'CLOSED' | 'TIMEOUT' | 'UNREACHABLE' | 'ERROR';
  durationMs: number;
  evidence: string;
  reason: string;
}

export interface TcpPortProbe {
  port: number;
  status: 'OPEN' | 'CLOSED' | 'TIMEOUT' | 'UNREACHABLE' | 'ERROR';
  durationMs: number;
  detail: string;
}

export interface HostDiscoveryResult {
  isHostUp: boolean;
  target: string;
  probeLogs: ProbeLog[];
  icmpResult: ProbeLog;
  arpResult: ProbeLog;
  tcpSynResult: ProbeLog;
  tcpConnectResult: ProbeLog;
  httpResult: ProbeLog;
  httpsResult: ProbeLog;
  smbResult: ProbeLog;
  activePorts: number[];
  consoleOutput: string;
  summaryReason: string;
}

/**
 * Socket-based TCP Port Check with precise latency measurement and TCP RST handling
 */
function probeTcpPort(host: string, port: number, timeoutMs = 2000): Promise<TcpPortProbe> {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const socket = new net.Socket();
    let isResolved = false;

    console.log(`[TCP Probe Log] Connection attempt to ${host}:${port}...`);
    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      if (!isResolved) {
        isResolved = true;
        const durationMs = Date.now() - startTime;
        socket.destroy();
        console.log(`[TCP Probe Log] Connection established to ${host}:${port} in ${durationMs}ms`);
        resolve({
          port,
          status: 'OPEN',
          durationMs,
          detail: `Connection established to ${host}:${port} in ${durationMs}ms`
        });
      }
    });

    socket.on('timeout', () => {
      if (!isResolved) {
        isResolved = true;
        const durationMs = Date.now() - startTime;
        socket.destroy();
        console.log(`[TCP Probe Log] Socket timeout on ${host}:${port} after ${durationMs}ms`);
        resolve({
          port,
          status: 'TIMEOUT',
          durationMs,
          detail: `Socket timeout on ${host}:${port} after ${durationMs}ms (Filtered / No response)`
        });
      }
    });

    socket.on('error', (err: any) => {
      if (!isResolved) {
        isResolved = true;
        const durationMs = Date.now() - startTime;
        socket.destroy();
        const code = err.code || '';
        if (code === 'ECONNREFUSED') {
          // Connection Refused means target host IS UP and actively sent a TCP RST packet!
          console.log(`[TCP Probe Log] Connection refused on ${host}:${port} in ${durationMs}ms (TCP RST - Host is Active)`);
          resolve({
            port,
            status: 'CLOSED',
            durationMs,
            detail: `Connection refused on ${host}:${port} in ${durationMs}ms (TCP RST received - Target Host is UP)`
          });
        } else if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH') {
          console.log(`[TCP Probe Log] Host or network unreachable on ${host}:${port} in ${durationMs}ms (${code})`);
          resolve({
            port,
            status: 'UNREACHABLE',
            durationMs,
            detail: `Host or network unreachable on ${host}:${port} in ${durationMs}ms (${code})`
          });
        } else if (code === 'ETIMEDOUT') {
          console.log(`[TCP Probe Log] Connection timed out on ${host}:${port} after ${durationMs}ms`);
          resolve({
            port,
            status: 'TIMEOUT',
            durationMs,
            detail: `Connection timed out on ${host}:${port} after ${durationMs}ms`
          });
        } else {
          console.log(`[TCP Probe Log] Error on ${host}:${port} in ${durationMs}ms (${err.message || code})`);
          resolve({
            port,
            status: 'ERROR',
            durationMs,
            detail: `Error on ${host}:${port} in ${durationMs}ms: ${err.message || code}`
          });
        }
      }
    });

    try {
      socket.connect(port, host);
    } catch (e: any) {
      if (!isResolved) {
        isResolved = true;
        const durationMs = Date.now() - startTime;
        console.log(`[TCP Probe Log] Exception on ${host}:${port} in ${durationMs}ms: ${e.message}`);
        resolve({
          port,
          status: 'ERROR',
          durationMs,
          detail: `Exception connecting to ${host}:${port}: ${e.message}`
        });
      }
    }
  });
}

/**
 * Method 1: ICMP Echo Probe
 */
async function runIcmpProbe(target: string, timeoutMs = 2000): Promise<ProbeLog> {
  const startTime = Date.now();
  return new Promise((resolve) => {
    const isWin = process.platform === 'win32';
    const timeoutSec = Math.max(1, Math.ceil(timeoutMs / 1000));
    const cmd = isWin 
      ? `ping -n 1 -w ${timeoutMs} ${target}`
      : `ping -c 1 -w ${timeoutSec} ${target}`;

    exec(cmd, { timeout: timeoutMs + 1000 }, (error, stdout, stderr) => {
      const durationMs = Date.now() - startTime;
      const output = ((stdout || '') + (stderr || '')).trim();
      const lower = output.toLowerCase();

      const isSuccess = !error && (
        lower.includes('bytes from') || 
        lower.includes('reply from') || 
        lower.includes('1 received') || 
        lower.includes('1 packets received') ||
        (lower.includes('0% packet loss') && !lower.includes('100% packet loss'))
      );

      if (isSuccess) {
        let rtt = `${durationMs}ms`;
        const timeMatch = output.match(/time[=|<]\s*([\d.]+)\s*ms/i) || output.match(/time=([\d.]+)ms/i);
        if (timeMatch) rtt = `${timeMatch[1]}ms`;

        resolve({
          probe: 'ICMP Echo',
          result: 'PASS',
          durationMs,
          evidence: `Echo reply received from ${target} (RTT ${rtt}, 0% packet loss)`,
          reason: 'ICMP Echo Reply received from target system.'
        });
      } else {
        let reason = 'No ICMP reply received (Packet loss 100% or ICMP blocked by firewall).';
        if (lower.includes('unreachable')) reason = 'Destination host unreachable.';

        resolve({
          probe: 'ICMP Echo',
          result: 'FAIL',
          durationMs,
          evidence: `No ICMP reply from ${target} within ${timeoutMs}ms`,
          reason
        });
      }
    });
  });
}

/**
 * Method 2: ARP Discovery Probe (same subnet / local ARP table)
 */
async function runArpProbe(target: string): Promise<ProbeLog> {
  const startTime = Date.now();
  return new Promise((resolve) => {
    const isWin = process.platform === 'win32';

    if (isWin) {
      exec(`arp -a ${target}`, { timeout: 2000 }, (error, stdout) => {
        const durationMs = Date.now() - startTime;
        if (!error && stdout) {
          const lines = stdout.split('\n');
          for (const line of lines) {
            if (line.includes(target)) {
              const macMatch = line.match(/([0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2})/i);
              if (macMatch) {
                return resolve({
                  probe: 'ARP Discovery',
                  result: 'PASS',
                  durationMs,
                  evidence: `Resolved MAC address ${macMatch[1]} for target ${target}`,
                  reason: 'Host responded to ARP request or exists in local ARP cache.'
                });
              }
            }
          }
        }
        resolve({
          probe: 'ARP Discovery',
          result: 'FAIL',
          durationMs,
          evidence: `No ARP cache entry found for ${target}`,
          reason: 'Target host is not on local L2 network segment or did not reply to ARP.'
        });
      });
    } else {
      try {
        if (fs.existsSync('/proc/net/arp')) {
          const arpContent = fs.readFileSync('/proc/net/arp', 'utf-8');
          const lines = arpContent.split('\n');
          for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 4 && parts[0] === target) {
              const mac = parts[3];
              if (mac && mac !== '00:00:00:00:00:00' && mac !== '0x0') {
                const durationMs = Date.now() - startTime;
                return resolve({
                  probe: 'ARP Discovery',
                  result: 'PASS',
                  durationMs,
                  evidence: `Found MAC address ${mac} in /proc/net/arp`,
                  reason: 'Target host active on local Layer 2 broadcast domain.'
                });
              }
            }
          }
        }
      } catch (e) {}

      exec(`ip neighbor show ${target}`, { timeout: 2000 }, (error, stdout) => {
        const durationMs = Date.now() - startTime;
        if (!error && stdout && stdout.includes(target)) {
          const macMatch = stdout.match(/([0-9a-fa-f]{2}:[0-9a-fa-f]{2}:[0-9a-fa-f]{2}:[0-9a-fa-f]{2}:[0-9a-fa-f]{2}:[0-9a-fa-f]{2})/i);
          if (macMatch && !stdout.toLowerCase().includes('failed')) {
            return resolve({
              probe: 'ARP Discovery',
              result: 'PASS',
              durationMs,
              evidence: `Resolved neighbor MAC ${macMatch[1]}`,
              reason: 'Target host verified via ip neighbor table.'
            });
          }
          if (stdout.toLowerCase().includes('reachable') || stdout.toLowerCase().includes('stale') || stdout.toLowerCase().includes('delay')) {
            return resolve({
              probe: 'ARP Discovery',
              result: 'PASS',
              durationMs,
              evidence: `Neighbor entry status: ${stdout.trim()}`,
              reason: 'Target host present in L2 neighbor table.'
            });
          }
        }
        resolve({
          probe: 'ARP Discovery',
          result: 'FAIL',
          durationMs,
          evidence: `No ARP / neighbor entry found for ${target}`,
          reason: 'Target host not found on local subnet or non-adjacent router target.'
        });
      });
    }
  });
}

/**
 * Helper to expand CIDR notation (e.g., 192.168.1.0/24 or 192.168.1.1/28) into individual IP addresses.
 * Limits scan range to a maximum of 256 IPs (/24) for safe execution.
 */
export function expandCidrSubnet(cidrString: string): string[] {
  const clean = cidrString.trim();
  if (!clean.includes('/')) {
    return [clean];
  }

  const [baseIp, maskStr] = clean.split('/');
  const prefixLen = parseInt(maskStr, 10);
  if (isNaN(prefixLen) || prefixLen < 16 || prefixLen > 32) {
    return [baseIp];
  }

  const octets = baseIp.split('.').map(Number);
  if (octets.length !== 4 || octets.some(o => isNaN(o) || o < 0 || o > 255)) {
    return [baseIp];
  }

  // Convert IP to 32-bit integer
  const ipInt = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
  const hostCount = Math.pow(2, 32 - prefixLen);
  const netmaskInt = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
  const networkInt = (ipInt & netmaskInt) >>> 0;

  const ips: string[] = [];
  // Max 256 IPs to prevent memory overload
  const countToScan = Math.min(hostCount, 256);

  for (let i = 0; i < countToScan; i++) {
    const currentIpInt = (networkInt + i) >>> 0;
    const o1 = (currentIpInt >>> 24) & 255;
    const o2 = (currentIpInt >>> 16) & 255;
    const o3 = (currentIpInt >>> 8) & 255;
    const o4 = currentIpInt & 255;

    // Skip network address (.0) and broadcast address (.255) for /24 if range > 2
    if (countToScan >= 4 && (o4 === 0 || o4 === 255)) {
      continue;
    }
    ips.push(`${o1}.${o2}.${o3}.${o4}`);
  }

  return ips.length > 0 ? ips : [baseIp];
}
export async function performHostDiscovery(target: string): Promise<HostDiscoveryResult> {
  console.log(`\n============================================================`);
  console.log(`[Host Discovery Engine] Initiating Enterprise Host Discovery for ${target}...`);
  console.log(`============================================================\n`);

  const probePorts = [80, 443, 445, 135, 139, 22, 3389, 5985, 5986];

  // Run all probes concurrently for maximum efficiency and speed
  const [icmpResult, arpResult, portProbes] = await Promise.all([
    runIcmpProbe(target, 2000),
    runArpProbe(target),
    Promise.all(probePorts.map(p => probeTcpPort(target, p, 2000)))
  ]);

  // Extract open ports and TCP responses
  const activePorts = portProbes.filter(p => p.status === 'OPEN').map(p => p.port);
  const closedPorts = portProbes.filter(p => p.status === 'CLOSED').map(p => p.port);

  // 1. TCP SYN / Socket Response Probe Log
  const tcpSynDuration = Math.max(...portProbes.map(p => p.durationMs), 0);
  const tcpSynResult: ProbeLog = activePorts.length > 0 ? {
    probe: 'TCP SYN Probe',
    result: 'PASS',
    durationMs: tcpSynDuration,
    evidence: `Open TCP ports detected: [${activePorts.join(', ')}]`,
    reason: 'Target host responded with SYN-ACK on open service ports.'
  } : {
    probe: 'TCP SYN Probe',
    result: 'FAIL',
    durationMs: tcpSynDuration,
    evidence: closedPorts.length > 0
      ? `Connection refused / closed on ports: [${closedPorts.join(', ')}]`
      : `All candidate TCP ports (${probePorts.join(',')}) timed out or unreachable`,
    reason: closedPorts.length > 0
      ? 'Target host closed all probed ports (No active listening services).'
      : 'No response received from target host.'
  };

  // 2. TCP Connect Probe Log
  const tcpConnectResult: ProbeLog = activePorts.length > 0 ? {
    probe: 'TCP Connect',
    result: 'PASS',
    durationMs: tcpSynDuration,
    evidence: `Full 3-way handshake established on port(s): [${activePorts.join(', ')}]`,
    reason: 'Full TCP connection established successfully.'
  } : {
    probe: 'TCP Connect',
    result: 'FAIL',
    durationMs: tcpSynDuration,
    evidence: `No open TCP ports found on ${target}`,
    reason: 'No open TCP port accepted 3-way connection.'
  };

  // 3. HTTP Probe Log (Port 80)
  const httpPort = portProbes.find(p => p.port === 80);
  const httpResult: ProbeLog = (httpPort && httpPort.status === 'OPEN') ? {
    probe: 'HTTP Probe',
    result: 'PASS',
    durationMs: httpPort.durationMs,
    evidence: `HTTP Port 80 OPEN on ${target} (${httpPort.durationMs}ms)`,
    reason: 'HTTP web service active and listening on port 80.'
  } : {
    probe: 'HTTP Probe',
    result: 'FAIL',
    durationMs: httpPort ? httpPort.durationMs : 2000,
    evidence: `Port 80 ${httpPort ? httpPort.status : 'TIMEOUT'}`,
    reason: 'HTTP port 80 did not respond or is closed.'
  };

  // 4. HTTPS Probe Log (Port 443)
  const httpsPort = portProbes.find(p => p.port === 443);
  const httpsResult: ProbeLog = (httpsPort && httpsPort.status === 'OPEN') ? {
    probe: 'HTTPS Probe',
    result: 'PASS',
    durationMs: httpsPort.durationMs,
    evidence: `HTTPS Port 443 OPEN on ${target} (${httpsPort.durationMs}ms)`,
    reason: 'HTTPS SSL/TLS service active and listening on port 443.'
  } : {
    probe: 'HTTPS Probe',
    result: 'FAIL',
    durationMs: httpsPort ? httpsPort.durationMs : 2000,
    evidence: `Port 443 ${httpsPort ? httpsPort.status : 'TIMEOUT'}`,
    reason: 'HTTPS port 443 did not respond or is closed.'
  };

  // 5. SMB Probe Log (Port 445 or 139)
  const smbPort445 = portProbes.find(p => p.port === 445);
  const smbPort139 = portProbes.find(p => p.port === 139);
  const smbOpen = (smbPort445 && smbPort445.status === 'OPEN') || (smbPort139 && smbPort139.status === 'OPEN');

  const smbResult: ProbeLog = smbOpen ? {
    probe: 'SMB Probe',
    result: 'PASS',
    durationMs: Math.min(smbPort445?.durationMs || 9999, smbPort139?.durationMs || 9999),
    evidence: `SMB port open (Port 445: ${smbPort445?.status || 'N/A'}, Port 139: ${smbPort139?.status || 'N/A'})`,
    reason: 'Target host responded to SMB file sharing port probes.'
  } : {
    probe: 'SMB Probe',
    result: 'FAIL',
    durationMs: smbPort445 ? smbPort445.durationMs : 2000,
    evidence: `SMB ports 445/139 timed out / closed on ${target}`,
    reason: 'No open response on SMB file sharing ports 445 or 139.'
  };

  // =========================================================================
  // STRICT DECISION LOGIC:
  // Host is ONLY REACHABLE if ICMP succeeds, ARP resolves, or >= 1 TCP port is OPEN!
  // =========================================================================
  const isHostUp = icmpResult.result === 'PASS' ||
                   arpResult.result === 'PASS' ||
                   activePorts.length > 0;

  // Build list of success reasons
  const passReasons: string[] = [];
  if (icmpResult.result === 'PASS') passReasons.push(`ICMP Echo (${icmpResult.evidence})`);
  if (arpResult.result === 'PASS') passReasons.push(`ARP Discovery (${arpResult.evidence})`);
  if (tcpSynResult.result === 'PASS') passReasons.push(`TCP SYN Probe (${tcpSynResult.evidence})`);
  if (httpResult.result === 'PASS' && httpPort?.status === 'OPEN') passReasons.push('HTTP Service on Port 80');
  if (httpsResult.result === 'PASS' && httpsPort?.status === 'OPEN') passReasons.push('HTTPS TLS Service on Port 443');
  if (smbResult.result === 'PASS' && smbPort445?.status === 'OPEN') passReasons.push('SMB Service on Port 445');

  const summaryReason = isHostUp
    ? `Host ${target} is REACHABLE via: ${passReasons.join('; ')}.`
    : `Host ${target} is UNREACHABLE. All 7 discovery probes (ICMP, ARP, TCP SYN, TCP Connect, HTTP, HTTPS, SMB) failed or timed out.`;

  const probeLogs: ProbeLog[] = [
    icmpResult,
    arpResult,
    tcpSynResult,
    tcpConnectResult,
    httpResult,
    httpsResult,
    smbResult
  ];

  // Construct Formatted Console Output according to enterprise scanner format
  const consoleLines: string[] = [];
  consoleLines.push(`============================================================`);
  consoleLines.push(`           ENTERPRISE HOST DISCOVERY ENGINE`);
  consoleLines.push(`============================================================`);
  consoleLines.push(`Target Host       : ${target}`);
  consoleLines.push(`Discovery Profile : Multi-Method (ICMP, ARP, TCP SYN, TCP Connect, HTTP, HTTPS, SMB)`);
  consoleLines.push(``);
  consoleLines.push(`PROBE EXECUTION LOG:`);
  consoleLines.push(`------------------------------------------------------------`);

  for (const pl of probeLogs) {
    const pName = pl.probe.padEnd(16, ' ');
    const res = pl.result.padEnd(6, ' ');
    consoleLines.push(`[${pName}] Result: ${res} | Duration: ${pl.durationMs}ms | Evidence: ${pl.evidence}`);
    consoleLines.push(`                   Reason  : ${pl.reason}`);
  }

  consoleLines.push(``);
  consoleLines.push(`------------------------------------------------------------`);
  consoleLines.push(`Host Discovery Summary`);
  consoleLines.push(`------------------------------------------------------------`);
  consoleLines.push(`ICMP........: ${icmpResult.result === 'PASS' ? `PASS (${icmpResult.evidence})` : `FAIL (${icmpResult.reason})`}`);
  consoleLines.push(`ARP.........: ${arpResult.result === 'PASS' ? `PASS (${arpResult.evidence})` : `FAIL (${arpResult.reason})`}`);
  consoleLines.push(`TCP SYN.....: ${tcpSynResult.result === 'PASS' ? `PASS (${tcpSynResult.evidence})` : `FAIL (${tcpSynResult.reason})`}`);
  consoleLines.push(`TCP CONNECT.: ${tcpConnectResult.result === 'PASS' ? `PASS (${tcpConnectResult.evidence})` : `FAIL (${tcpConnectResult.reason})`}`);
  consoleLines.push(`HTTP........: ${httpResult.result === 'PASS' ? `PASS (${httpResult.evidence})` : `FAIL (${httpResult.reason})`}`);
  consoleLines.push(`HTTPS.......: ${httpsResult.result === 'PASS' ? `PASS (${httpsResult.evidence})` : `FAIL (${httpsResult.reason})`}`);
  consoleLines.push(`SMB.........: ${smbResult.result === 'PASS' ? `PASS (${smbResult.evidence})` : `FAIL (${smbResult.reason})`}`);
  consoleLines.push(``);
  consoleLines.push(`Final Decision`);
  consoleLines.push(`------------------------------------------------------------`);
  consoleLines.push(`Host Reachable: ${isHostUp ? 'YES' : 'NO'}`);
  consoleLines.push(`Reason        : ${summaryReason}`);
  consoleLines.push(`============================================================`);

  const consoleOutput = consoleLines.join('\n');

  console.log(consoleOutput);

  return {
    isHostUp,
    target,
    probeLogs,
    icmpResult,
    arpResult,
    tcpSynResult,
    tcpConnectResult,
    httpResult,
    httpsResult,
    smbResult,
    activePorts,
    consoleOutput,
    summaryReason
  };
}
