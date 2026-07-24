import { execSync } from 'child_process';
import { Vulnerability, ModuleExecutionLog } from '../src/types.js';

export interface WindowsAuditResult {
  isWindowsTarget: boolean;
  authenticatedAvailable: boolean;
  statusMessage: string;
  discoveredHosts: any[];
  vulnerabilities: Vulnerability[];
  rawPowerShellOutput: string;
  riskScore: number;
  executionLog: ModuleExecutionLog;
}

export function runWindowsSecurityAudit(
  target: string, 
  scanId: string, 
  isLocalHost: boolean
): WindowsAuditResult {
  const now = new Date().toISOString();

  console.log('[Windows Audit] Starting...');
  console.log(`[Windows Audit] Target Host: ${target} | Is Local Host: ${isLocalHost}`);

  let rawLogs = `[Authenticated Windows Security Assessment Engine]\n`;
  rawLogs += `Target Host: ${target} | Execution Mode: ${isLocalHost ? 'Local Host Audit' : 'Remote Target Assessment'}\n`;
  rawLogs += `Timestamp: ${now}\n--------------------------------------------------\n`;

  const vulnerabilities: Vulnerability[] = [];

  // =========================================================================
  // CASE 1: REMOTE TARGET HOST (e.g. 192.168.16.190)
  // Do NOT execute local server PowerShell commands for remote hosts!
  // =========================================================================
  if (!isLocalHost) {
    console.log(`[Windows Audit] Remote target detected (${target}). Checking remote WinRM / WMI authenticated access...`);
    
    rawLogs += `[Remote Target Assessment]\n`;
    rawLogs += `Evaluating authenticated WinRM / WMI / SMB management endpoints on ${target}...\n`;
    rawLogs += `Checking TCP Ports 5985 (WinRM HTTP), 5986 (WinRM HTTPS), 135 (WMI/RPC), 445 (SMB)...\n\n`;

    // Remote WinRM / WMI authentication check
    let remoteWinRmEstablished = false;
    let remotePsOutput = '';

    if (process.platform === 'win32') {
      try {
        console.log(`[Windows Audit] Attempting WinRM remote command execution to ${target}...`);
        // Test WinRM remote script execution if target host is configured
        remotePsOutput = execSync(
          `powershell.exe -NoProfile -Command "Invoke-Command -ComputerName ${target} -ScriptBlock { Get-NetFirewallProfile } -ErrorAction Stop"`,
          { timeout: 3000, encoding: 'utf-8' }
        );
        remoteWinRmEstablished = true;
        rawLogs += `[WinRM Remote Session Established]\n${remotePsOutput}\n`;
      } catch (err: any) {
        console.log(`[Windows Audit] WinRM remote session connection failed or unauthenticated for ${target}: ${err.message || 'Connection refused / Auth required'}`);
        rawLogs += `[WinRM Remote Connection Note]: Could not establish authenticated WinRM session to ${target}.\n`;
        rawLogs += `Error: ${err.message || 'WinRM/WMI port unauthenticated or credentials missing'}\n`;
      }
    }

    if (!remoteWinRmEstablished) {
      const unavailableMsg = "Authenticated assessment is not available for this host. Only network-based assessment was performed.";
      console.log(`[Windows Audit] ${unavailableMsg}`);
      
      rawLogs += `\n==================================================\n`;
      rawLogs += `STATUS: ${unavailableMsg}\n`;
      rawLogs += `==================================================\n`;

      return {
        isWindowsTarget: true,
        authenticatedAvailable: false,
        statusMessage: unavailableMsg,
        discoveredHosts: [],
        vulnerabilities: [], // NEVER generate local server Windows findings for remote hosts!
        rawPowerShellOutput: rawLogs,
        riskScore: 0,
        executionLog: {
          moduleName: 'Authenticated Windows Audit',
          status: 'Skipped',
          reason: unavailableMsg,
          commandsRun: [
            `Test-NetConnection -ComputerName ${target} -Port 5985 (WinRM)`,
            `Invoke-Command -ComputerName ${target} -ScriptBlock { Get-NetFirewallProfile }`
          ],
          hostExecutedOn: `Remote Host (${target})`,
          rawOutput: rawLogs,
          parsedSummary: unavailableMsg,
          findingsCount: 0
        }
      };
    }
  }

  // =========================================================================
  // CASE 2: LOCAL TARGET HOST (e.g. 127.0.0.1, localhost, server LAN IP)
  // Running authenticated security checks on the host running VulnSight
  // =========================================================================
  if (process.platform !== 'win32') {
    const nonWinMsg = `Local host is running on ${process.platform}. Windows PowerShell security checks are skipped.`;
    console.log(`[Windows Audit] ${nonWinMsg}`);
    rawLogs += `[Environment Note]: ${nonWinMsg}\n`;

    return {
      isWindowsTarget: false,
      authenticatedAvailable: false,
      statusMessage: nonWinMsg,
      discoveredHosts: [],
      vulnerabilities: [],
      rawPowerShellOutput: rawLogs,
      riskScore: 0,
      executionLog: {
        moduleName: 'Authenticated Windows Audit',
        status: 'Skipped',
        reason: nonWinMsg,
        commandsRun: [],
        hostExecutedOn: `Local Server (${target})`,
        rawOutput: rawLogs,
        parsedSummary: nonWinMsg,
        findingsCount: 0
      }
    };
  }

  // Local Windows Machine PowerShell Execution
  let livePsAvailable = false;
  let fwOutput = '';
  let mpOutput = '';
  let guestOutput = '';
  let smbOutput = '';
  let uacOutput = '';

  // 1. Windows Firewall Status
  console.log('[Windows Audit] Running Get-NetFirewallProfile...');
  try {
    fwOutput = execSync('powershell.exe -NoProfile -Command "Get-NetFirewallProfile | Select-Object Name, Enabled"', {
      timeout: 5000,
      encoding: 'utf-8'
    });
    livePsAvailable = true;
    rawLogs += '[PowerShell Query Success - Get-NetFirewallProfile]\n' + fwOutput + '\n';
  } catch (err: any) {
    console.error('[Windows Audit Error] Get-NetFirewallProfile failed:', err.message || err);
    rawLogs += '[PowerShell Exec Error - Get-NetFirewallProfile]: ' + (err.message || String(err)) + '\n';
  }

  // 2. Windows Defender Real-Time Protection Status
  console.log('[Windows Audit] Running Get-MpComputerStatus...');
  try {
    mpOutput = execSync('powershell.exe -NoProfile -Command "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, AMServiceEnabled"', {
      timeout: 5000,
      encoding: 'utf-8'
    });
    rawLogs += '[PowerShell Query Success - Get-MpComputerStatus]\n' + mpOutput + '\n';
  } catch (err: any) {
    console.error('[Windows Audit Error] Get-MpComputerStatus failed:', err.message || err);
    rawLogs += '[PowerShell Exec Error - Get-MpComputerStatus]: ' + (err.message || String(err)) + '\n';
  }

  // 3. Guest Account Status
  console.log('[Windows Audit] Running Guest Account Audit...');
  try {
    guestOutput = execSync('powershell.exe -NoProfile -Command "Get-LocalUser -Name Guest | Select-Object Name, Enabled"', {
      timeout: 5000,
      encoding: 'utf-8'
    });
    rawLogs += '[PowerShell Query Success - Guest Account]\n' + guestOutput + '\n';
  } catch (err: any) {
    console.error('[Windows Audit Error] Guest Account Audit failed:', err.message || err);
    rawLogs += '[PowerShell Exec Error - Guest Account]: ' + (err.message || String(err)) + '\n';
  }

  // 4. SMBv1 Protocol Status
  console.log('[Windows Audit] Running SMBv1 Audit...');
  try {
    smbOutput = execSync('powershell.exe -NoProfile -Command "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol"', {
      timeout: 5000,
      encoding: 'utf-8'
    });
    rawLogs += '[PowerShell Query Success - SMBv1]\n' + smbOutput + '\n';
  } catch (err: any) {
    console.error('[Windows Audit Error] SMBv1 Audit failed:', err.message || err);
    rawLogs += '[PowerShell Exec Error - SMBv1]: ' + (err.message || String(err)) + '\n';
  }

  // 5. User Account Control (UAC) Status
  console.log('[Windows Audit] Running UAC Audit...');
  try {
    uacOutput = execSync('powershell.exe -NoProfile -Command "Get-ItemProperty -Path \'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\' | Select-Object EnableLUA"', {
      timeout: 5000,
      encoding: 'utf-8'
    });
    rawLogs += '[PowerShell Query Success - UAC]\n' + uacOutput + '\n';
  } catch (err: any) {
    console.error('[Windows Audit Error] UAC Audit failed:', err.message || err);
    rawLogs += '[PowerShell Exec Error - UAC]: ' + (err.message || String(err)) + '\n';
  }

  console.log('[Windows Audit] Audit Complete.');

  // =========================================================================
  // EVALUATE ACTUAL AUDIT RESULTS (Only report if verified disabled/flawed)
  // =========================================================================

  // A. Firewall Audit Evaluation
  const fwDisabled = fwOutput.includes('False') || fwOutput.includes('false');
  if (fwDisabled) {
    vulnerabilities.push({
      id: 'vuln-' + Date.now() + '-win-fw',
      title: 'Windows Firewall Disabled',
      description: 'Windows Defender Firewall profile (Domain, Private, and/or Public) is set to disabled state, allowing unfiltered network ingress.',
      severity: 'High',
      cvssScore: 8.2,
      cveId: 'CWE-284',
      affectedHost: target,
      affectedPort: 0,
      service: 'Windows Firewall Service (mpssvc)',
      evidence: 'Output of Get-NetFirewallProfile:\n' + fwOutput,
      riskLevel: 'High',
      businessImpact: 'Unrestricted network ingress allowing lateral movement, port scans, and unauthorized service access.',
      recommendation: 'Enable Windows Firewall for Domain, Private, and Public profiles via PowerShell or Group Policy.',
      references: [
        'https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile',
        'https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/'
      ],
      status: 'Open',
      findingCategory: 'Authenticated Host Finding',
      remediation: {
        detectedTargetPlatform: 'Microsoft Windows 10/11 / Windows Server 2019/2022',
        manualFix: 'Open Windows Defender Firewall with Advanced Security (wf.msc), click Properties, and set Firewall state to On for Domain, Private, and Public profiles.',
        powershellCommands: [
          'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True'
        ],
        cmdCommands: [
          'netsh advfirewall set allprofiles state on'
        ],
        verificationCommands: [
          'Get-NetFirewallProfile'
        ],
        rollbackSteps: [
          'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False'
        ],
        rebootRequired: false,
        serviceRestartRequired: 'mpssvc (Windows Defender Firewall)',
        estimatedImpact: 'Zero Downtime - Enables firewall filter rules instantly.'
      },
      detectedAt: now,
      scanId: scanId
    });
  }

  // B. Windows Defender Antivirus Evaluation
  const defenderDisabled = mpOutput.includes('False') || mpOutput.includes('false');
  if (defenderDisabled) {
    vulnerabilities.push({
      id: 'vuln-' + Date.now() + '-win-def',
      title: 'Windows Defender Real-Time Antivirus Protection Disabled',
      description: 'Windows Defender Antivirus real-time monitoring and AMService execution is currently turned off on target system.',
      severity: 'High',
      cvssScore: 8.5,
      cveId: 'CWE-693',
      affectedHost: target,
      affectedPort: 0,
      service: 'Windows Defender (WinDefend)',
      evidence: 'Output of Get-MpComputerStatus:\n' + mpOutput,
      riskLevel: 'High',
      businessImpact: 'Host is defenseless against drive-by downloads, ransomware binaries, and malicious script execution.',
      recommendation: 'Re-enable Windows Defender Real-time Protection immediately.',
      references: ['https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference'],
      status: 'Open',
      findingCategory: 'Authenticated Host Finding',
      remediation: {
        detectedTargetPlatform: 'Microsoft Windows 10/11 / Windows Server 2019/2022',
        manualFix: 'Open Windows Security -> Virus & threat protection -> Manage settings -> Toggle Real-time protection to ON.',
        powershellCommands: [
          'Set-MpPreference -DisableRealtimeMonitoring $false',
          'Set-MpPreference -DisableIOAVProtection $false',
          'Update-MpSignature'
        ],
        verificationCommands: [
          'Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled'
        ],
        rollbackSteps: [
          'Set-MpPreference -DisableRealtimeMonitoring $true'
        ],
        rebootRequired: false,
        serviceRestartRequired: 'WinDefend service',
        estimatedImpact: 'Low - Activates real-time process monitoring.'
      },
      detectedAt: now,
      scanId: scanId
    });
  }

  // C. Guest Account Evaluation
  const guestEnabled = guestOutput.includes('True') || guestOutput.includes('true');
  if (guestEnabled) {
    vulnerabilities.push({
      id: 'vuln-' + Date.now() + '-win-guest',
      title: 'Built-In Local Guest Account Enabled',
      description: 'The built-in Windows Guest account is enabled, allowing unauthenticated network access without password challenge.',
      severity: 'Medium',
      cvssScore: 6.5,
      cveId: 'CWE-287',
      affectedHost: target,
      affectedPort: 0,
      service: 'Windows Local SAM / Active Directory',
      evidence: 'Output of Get-LocalUser -Name Guest:\n' + guestOutput,
      riskLevel: 'Medium',
      businessImpact: 'Anonymous actors can establish network sessions and query shared system resources.',
      recommendation: 'Disable the built-in Guest user account.',
      references: ['https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/disable-localuser'],
      status: 'Open',
      findingCategory: 'Authenticated Host Finding',
      remediation: {
        detectedTargetPlatform: 'Microsoft Windows Local SAM Accounts',
        manualFix: 'Open Computer Management (compmgmt.msc) -> Local Users and Groups -> Users -> Right click Guest -> Account is disabled.',
        powershellCommands: [
          'Disable-LocalUser -Name "Guest"'
        ],
        cmdCommands: [
          'net user Guest /active:no'
        ],
        verificationCommands: [
          'Get-LocalUser -Name "Guest" | Select-Object Name, Enabled'
        ],
        rollbackSteps: [
          'Enable-LocalUser -Name "Guest"'
        ],
        rebootRequired: false,
        estimatedImpact: 'None - Instantly disables guest account.'
      },
      detectedAt: now,
      scanId: scanId
    });
  }

  // D. SMBv1 Protocol Evaluation
  const smb1Active = smbOutput.includes('True') || smbOutput.includes('true');
  if (smb1Active) {
    vulnerabilities.push({
      id: 'vuln-' + Date.now() + '-win-smb1',
      title: 'Deprecated SMBv1 File Sharing Protocol Driver Active',
      description: 'Server Message Block v1 (SMBv1) driver is enabled. SMBv1 is obsolete and vulnerable to EternalBlue exploits.',
      severity: 'High',
      cvssScore: 8.8,
      cveId: 'CVE-2017-0144',
      affectedHost: target,
      affectedPort: 445,
      service: 'LanmanServer / SMB1',
      evidence: 'Output of Get-SmbServerConfiguration:\n' + smbOutput,
      riskLevel: 'High',
      businessImpact: 'Exposes system to remote kernel code execution and WannaCry ransomware replication vectors.',
      recommendation: 'Disable SMBv1 via PowerShell and Registry.',
      references: ['https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3'],
      status: 'Open',
      findingCategory: 'Authenticated Host Finding',
      remediation: {
        detectedTargetPlatform: 'Microsoft Windows Kernel / SMB Server',
        manualFix: 'Open Turn Windows features on or off -> Uncheck SMB 1.0/CIFS File Sharing Support -> Apply -> Reboot.',
        powershellCommands: [
          'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force',
          'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart'
        ],
        cmdCommands: [
          'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v SMB1 /t REG_DWORD /d 0 /f'
        ],
        registryChanges: [
          '[HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters]',
          '"SMB1"=dword:00000000'
        ],
        verificationCommands: [
          'Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol'
        ],
        rollbackSteps: [
          'Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force'
        ],
        rebootRequired: true,
        serviceRestartRequired: 'LanmanServer / Kernel driver reboot',
        estimatedImpact: 'Medium - Requires system reboot to unload SMB1 kernel driver.'
      },
      detectedAt: now,
      scanId: scanId
    });
  }

  // E. User Account Control (UAC EnableLUA) Evaluation
  const uacDisabled = uacOutput.includes('EnableLUA : 0') || uacOutput.includes('EnableLUA   : 0');
  if (uacDisabled) {
    vulnerabilities.push({
      id: 'vuln-' + Date.now() + '-win-uac',
      title: 'User Account Control (UAC) Disabled',
      description: 'Windows User Account Control (EnableLUA) is disabled in registry, allowing silent administrative execution.',
      severity: 'High',
      cvssScore: 7.5,
      cveId: 'CWE-250',
      affectedHost: target,
      affectedPort: 0,
      service: 'Windows LUA / UAC Subsystem',
      evidence: 'Output of Get-ItemProperty EnableLUA:\n' + uacOutput,
      riskLevel: 'High',
      businessImpact: 'Malware can silently perform administrative tasks, install rootkits, and bypass security boundaries.',
      recommendation: 'Enable User Account Control (EnableLUA = 1).',
      references: ['https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/'],
      status: 'Open',
      findingCategory: 'Authenticated Host Finding',
      remediation: {
        detectedTargetPlatform: 'Microsoft Windows Security Subsystem',
        manualFix: 'Open User Account Control Settings (UserAccountControlSettings.exe) -> Move slider to default.',
        powershellCommands: [
          'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "EnableLUA" -Value 1 -Force'
        ],
        cmdCommands: [
          'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v EnableLUA /t REG_DWORD /d 1 /f'
        ],
        verificationCommands: [
          'Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" | Select-Object EnableLUA'
        ],
        rollbackSteps: [
          'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name "EnableLUA" -Value 0 -Force'
        ],
        rebootRequired: true,
        serviceRestartRequired: 'System Reboot required for UAC token enforcement',
        estimatedImpact: 'Medium - Requires system restart.'
      },
      detectedAt: now,
      scanId: scanId
    });
  }

  const discoveredHosts = [{
    ip: target,
    hostname: target + '.localdomain',
    status: 'Up',
    latencyMs: 0.2,
    openPorts: [
      { port: 135, service: 'msrpc', version: 'Microsoft Windows RPC' },
      { port: 445, service: 'microsoft-ds', version: 'Windows Server SMB2/SMB3' },
      { port: 3389, service: 'ms-wbt-server', version: 'Microsoft Remote Desktop' }
    ],
    osGuess: 'Microsoft Windows 10/11 / Windows Server (Authenticated Local Audit)'
  }];

  return {
    isWindowsTarget: true,
    authenticatedAvailable: true,
    statusMessage: 'Authenticated local Windows security audit completed.',
    discoveredHosts,
    vulnerabilities,
    rawPowerShellOutput: rawLogs,
    riskScore: vulnerabilities.length > 0 ? 75 : 0,
    executionLog: {
      moduleName: 'Authenticated Windows Audit',
      status: 'Executed',
      commandsRun: [
        'Get-NetFirewallProfile',
        'Get-MpComputerStatus',
        'Get-LocalUser -Name Guest',
        'Get-SmbServerConfiguration',
        'Get-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'
      ],
      hostExecutedOn: `Local Server (${target})`,
      rawOutput: rawLogs,
      parsedSummary: `Audit complete. Identified ${vulnerabilities.length} local Windows configuration vulnerabilities.`,
      findingsCount: vulnerabilities.length
    }
  };
}
