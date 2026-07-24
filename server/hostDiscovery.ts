import net from 'net';
import { exec } from 'child_process';
import fs from 'fs';

export interface TcpProbeDetail {
  port: number;
  status: 'OPEN' | 'CLOSED' | 'TIMEOUT' | 'UNREACHABLE' | 'ERROR';
  detail?: string;
}

export interface HostDiscoveryResult {
  isHostUp: boolean;
  pingResult: {
    passed: boolean;
    label: string;
    rawOutput?: string;
  };
  arpResult: {
    passed: boolean;
    label: string;
  };
  tcpProbes: TcpProbeDetail[];
  activePorts: number[];
  consoleOutput: string;
  summaryReason: string;
}

/**
 * Method 1: ICMP Echo (ping)
 */
async function runIcmpPing(target: string, timeoutMs = 2000): Promise<{ passed: boolean; label: string; rawOutput: string }> {
  return new Promise((resolve) => {
    const isWin = process.platform === 'win32';
    const timeoutSec = Math.max(1, Math.ceil(timeoutMs / 1000));
    const cmd = isWin 
      ? `ping -n 1 -w ${timeoutMs} ${target}`
      : `ping -c 1 -w ${timeoutSec} ${target}`;

    exec(cmd, { timeout: timeoutMs + 1000 }, (error, stdout, stderr) => {
      const output = ((stdout || '') + (stderr || '')).trim();
      const lower = output.toLowerCase();

      // Check success indicators
      const isSuccess = !error && (
        lower.includes('bytes from') || 
        lower.includes('reply from') || 
        lower.includes('1 received') || 
        lower.includes('1 packets received') ||
        (lower.includes('0% packet loss') && !lower.includes('100% packet loss'))
      );

      if (isSuccess) {
        let rttLabel = 'PASS';
        const timeMatch = output.match(/time[=|<]\s*([\d.]+)\s*ms/i) || output.match(/time=([\d.]+)ms/i);
        if (timeMatch) {
          rttLabel = `PASS (${timeMatch[1]}ms)`;
        } else if (lower.includes('time<1ms')) {
          rttLabel = 'PASS (<1ms)';
        } else {
          rttLabel = 'PASS';
        }
        resolve({ passed: true, label: rttLabel, rawOutput: output });
      } else {
        let failReason = 'FAIL (No ICMP reply)';
        if (lower.includes('destination host unreachable') || lower.includes('unreachable')) {
          failReason = 'FAIL (Host Unreachable)';
        } else if (lower.includes('100% packet loss') || lower.includes('100% loss')) {
          failReason = 'FAIL (100% Packet Loss)';
        } else if (error && error.killed) {
          failReason = 'FAIL (Timeout)';
        }
        resolve({ passed: false, label: failReason, rawOutput: output });
      }
    });
  });
}

/**
 * Method 2: ARP Cache Lookup
 */
async function runArpLookup(target: string): Promise<{ passed: boolean; label: string }> {
  return new Promise((resolve) => {
    const isWin = process.platform === 'win32';

    if (isWin) {
      exec(`arp -a ${target}`, { timeout: 2000 }, (error, stdout) => {
        if (!error && stdout) {
          const lines = stdout.split('\n');
          for (const line of lines) {
            if (line.includes(target)) {
              const macMatch = line.match(/([0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2}[:-][0-9a-fa-f]{2})/i);
              if (macMatch) {
                return resolve({ passed: true, label: `PASS (${macMatch[1]})` });
              }
              if (!line.toLowerCase().includes('invalid')) {
                return resolve({ passed: true, label: 'PASS' });
              }
            }
          }
        }
        resolve({ passed: false, label: 'FAIL (Not found in ARP table)' });
      });
    } else {
      // Linux: Check /proc/net/arp or ip neighbor
      try {
        if (fs.existsSync('/proc/net/arp')) {
          const arpContent = fs.readFileSync('/proc/net/arp', 'utf-8');
          const lines = arpContent.split('\n');
          for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 4 && parts[0] === target) {
              const mac = parts[3];
              if (mac && mac !== '00:00:00:00:00:00' && mac !== '0x0') {
                return resolve({ passed: true, label: `PASS (${mac})` });
              }
            }
          }
        }
      } catch (e) {}

      // Fallback command: ip neighbor show / arp
      exec(`ip neighbor show ${target}`, { timeout: 2000 }, (error, stdout) => {
        if (!error && stdout && stdout.includes(target)) {
          const macMatch = stdout.match(/([0-9a-fa-f]{2}:[0-9a-fa-f]{2}:[0-9a-fa-f]{2}:[0-9a-fa-f]{2}:[0-9a-fa-f]{2}:[0-9a-fa-f]{2})/i);
          if (macMatch && !stdout.toLowerCase().includes('failed')) {
            return resolve({ passed: true, label: `PASS (${macMatch[1]})` });
          }
          if (stdout.toLowerCase().includes('reachable') || stdout.toLowerCase().includes('stale') || stdout.toLowerCase().includes('delay')) {
            return resolve({ passed: true, label: 'PASS' });
          }
        }
        resolve({ passed: false, label: 'FAIL (Not found in ARP table)' });
      });
    }
  });
}

/**
 * Method 3: TCP Connect Probe to a single port
 */
function probeSingleTcpPort(host: string, port: number, timeoutMs = 2000): Promise<TcpProbeDetail> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let isResolved = false;

    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      if (!isResolved) {
        isResolved = true;
        socket.destroy();
        resolve({ port, status: 'OPEN', detail: 'Connection established' });
      }
    });

    socket.on('timeout', () => {
      if (!isResolved) {
        isResolved = true;
        socket.destroy();
        resolve({ port, status: 'TIMEOUT', detail: 'Connection timed out' });
      }
    });

    socket.on('error', (err: any) => {
      if (!isResolved) {
        isResolved = true;
        socket.destroy();
        const code = err.code || '';
        if (code === 'ECONNREFUSED') {
          // Target active TCP RST response -> Host is UP! Port is CLOSED.
          resolve({ port, status: 'CLOSED', detail: 'Connection refused (TCP RST)' });
        } else if (code === 'EHOSTUNREACH' || code === 'ENETUNREACH') {
          resolve({ port, status: 'UNREACHABLE', detail: 'Host or network unreachable' });
        } else if (code === 'ETIMEDOUT') {
          resolve({ port, status: 'TIMEOUT', detail: 'Socket connection timed out' });
        } else {
          resolve({ port, status: 'ERROR', detail: err.message || code });
        }
      }
    });

    socket.connect(port, host);
  });
}

/**
 * Full Host Discovery Pipeline implementing strict multi-method host detection.
 */
export async function performHostDiscovery(target: string): Promise<HostDiscoveryResult> {
  const portsToProbe = [80, 443, 135, 139, 445, 3389, 22, 5985, 5986];

  // Method 1: ICMP Echo (ping)
  const pingResult = await runIcmpPing(target, 2000);

  // Method 2: ARP cache lookup
  const arpResult = await runArpLookup(target);

  // Method 3: TCP connect to common ports (80,443,135,139,445,3389,22,5985,5986)
  const tcpProbes = await Promise.all(portsToProbe.map(p => probeSingleTcpPort(target, p, 2000)));

  // Determine active/open ports
  const activePorts = tcpProbes.filter(p => p.status === 'OPEN').map(p => p.port);

  // Determine if host responds via TCP (OPEN or CLOSED/RESET)
  const tcpResponded = tcpProbes.some(p => p.status === 'OPEN' || p.status === 'CLOSED');

  // Method 4: If ANY probe succeeds, consider the host reachable.
  const isHostUp = pingResult.passed || arpResult.passed || tcpResponded;

  // Build formatted console output matching expected enterprise scanner behavior
  const consoleLines: string[] = [];
  consoleLines.push('Host Discovery');
  consoleLines.push('----------------');
  consoleLines.push(`Ping........${pingResult.label}`);
  consoleLines.push(`ARP.........${arpResult.label}`);
  for (const probe of tcpProbes) {
    const padPort = `TCP ${probe.port}`.padEnd(12, '.');
    consoleLines.push(`${padPort}${probe.status}`);
  }
  consoleLines.push('');
  consoleLines.push('Final Result:');
  consoleLines.push(`HOST ${isHostUp ? 'REACHABLE' : 'UNREACHABLE'}`);

  const consoleOutput = consoleLines.join('\n');

  // Print exact output to Node server console
  console.log('\n[Host Discovery Engine Output]');
  console.log(consoleOutput);
  console.log('----------------------------------------\n');

  let summaryReason = '';
  if (isHostUp) {
    const reasons: string[] = [];
    if (pingResult.passed) reasons.push(`ICMP Ping (${pingResult.label})`);
    if (arpResult.passed) reasons.push(`ARP Resolution (${arpResult.label})`);
    if (activePorts.length > 0) reasons.push(`Open TCP Ports [${activePorts.join(', ')}]`);
    else if (tcpResponded) reasons.push('TCP Port RST/Refused Response');
    summaryReason = `Host ${target} is REACHABLE via ${reasons.join(', ')}.`;
  } else {
    summaryReason = `Host ${target} is UNREACHABLE. ICMP Ping failed, ARP lookup failed, and all TCP probes timed out / failed.`;
  }

  return {
    isHostUp,
    pingResult,
    arpResult,
    tcpProbes,
    activePorts,
    consoleOutput,
    summaryReason
  };
}
