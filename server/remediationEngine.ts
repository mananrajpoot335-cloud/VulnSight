export interface RemediationResult {
  detectedTargetPlatform: string;
  rootCause: string;
  technicalExplanation: string;
  manualFix: string;
  bashCommands?: string[];
  powershellCommands?: string[];
  cmdCommands?: string[];
  cliCommands?: string[];
  registryChanges?: string[];
  configFilePath?: string;
  configSnippets?: string[];
  verificationCommands?: string[];
  rollbackSteps?: string[];
  rebootRequired: boolean;
  serviceRestartRequired?: string;
  estimatedImpact: string;
  references: string[];
}

export function generateDynamicRemediation(
  target: string,
  port: number = 80,
  service: string = 'http',
  banner: string = '',
  vulnTitle: string = '',
  severity: string = 'Low',
  cveId: string = '',
  evidence: string = ''
): RemediationResult {
  const cleanTarget = target.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const targetLower = cleanTarget.toLowerCase();
  const serviceLower = (service || '').toLowerCase();
  const bannerLower = (banner || '').toLowerCase();
  const titleLower = (vulnTitle || '').toLowerCase();
  const cveLower = (cveId || '').toLowerCase();

  // 1. SERVICE EXISTENCE VERIFICATION GUARD
  if (port === 0 && !titleLower.includes('firewall') && !titleLower.includes('defender') && !titleLower.includes('guest')) {
    if (serviceLower.includes('closed') || serviceLower.includes('filtered')) {
      return {
        detectedTargetPlatform: 'Inactive / Closed Port',
        rootCause: 'Service port is not listening or is filtered by firewall rules.',
        technicalExplanation: `The target host ${cleanTarget} does not have an active service listening on port ${port}.`,
        manualFix: 'No remediation required. The affected service is not installed or active on this target.',
        rebootRequired: false,
        estimatedImpact: 'None',
        references: ['https://nvd.nist.gov/']
      };
    }
  }

  // 2. WINDOWS DEFENDER FIREWALL / INGRESS FILTERING
  if (titleLower.includes('firewall') || titleLower.includes('ingress filtering') || titleLower.includes('mpssvc')) {
    return {
      detectedTargetPlatform: 'Microsoft Windows Security Engine (Windows Defender Firewall)',
      rootCause: 'Windows Defender Firewall profile (Domain, Private, or Public) is turned off or ingress filtering rules are disabled.',
      technicalExplanation: `Target system ${cleanTarget} has disabled or permissive firewall profiles. Unfiltered network ingress permits unauthorized scanning, lateral movement, and direct exploitation of exposed services.`,
      manualFix: 'Enable Windows Defender Firewall for Domain, Private, and Public profiles immediately using PowerShell or netsh command line.',
      powershellCommands: [
        'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True'
      ],
      cmdCommands: [
        'netsh advfirewall set allprofiles state on'
      ],
      verificationCommands: [
        'Get-NetFirewallProfile | Select-Object Name, Enabled'
      ],
      rollbackSteps: [
        'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False'
      ],
      rebootRequired: false,
      serviceRestartRequired: 'mpssvc (Windows Defender Firewall)',
      estimatedImpact: 'Zero Downtime - Enables network packet filtering instantly.',
      references: [
        'https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile',
        'https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/'
      ]
    };
  }

  // 3. SMB / UNENCRYPTED FILE SHARING / SMB SIGNING
  if (titleLower.includes('smb') || titleLower.includes('microsoft-ds') || serviceLower.includes('microsoft-ds') || port === 445) {
    return {
      detectedTargetPlatform: 'Windows Server / Active Directory (SMB File Sharing - TCP 445/139)',
      rootCause: 'SMB message signing is not required or legacy unencrypted SMB protocol is enabled.',
      technicalExplanation: `Target ${cleanTarget} exposes SMB file sharing over TCP port 445 without enforcing mandatory packet signing. Attackers on the local LAN can perform Man-in-the-Middle (MitM) relay attacks or steal session hashes.`,
      manualFix: 'Enforce SMB packet signing in Group Policy or Windows Registry and disable legacy SMBv1 protocol.',
      powershellCommands: [
        'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force',
        'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force'
      ],
      cmdCommands: [
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f',
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v SMB1 /t REG_DWORD /d 0 /f'
      ],
      registryChanges: [
        '[HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters]',
        '"RequireSecuritySignature"=dword:00000001',
        '"SMB1"=dword:00000000'
      ],
      verificationCommands: [
        'Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSMB1Protocol'
      ],
      rollbackSteps: [
        'Set-SmbServerConfiguration -RequireSecuritySignature $false -Force'
      ],
      rebootRequired: false,
      serviceRestartRequired: 'LanmanServer (Server Service)',
      estimatedImpact: 'Low - Restricts unsigned SMB client negotiations.',
      references: ['https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-of-smb-signing']
    };
  }

  // 4. MSRPC ENDPOINT MAPPER
  if (titleLower.includes('msrpc') || titleLower.includes('rpc endpoint') || port === 135) {
    return {
      detectedTargetPlatform: 'Microsoft Windows RPC Subsystem (TCP 135)',
      rootCause: 'MSRPC Endpoint Mapper port 135 is open to untrusted network subnets.',
      technicalExplanation: `Target ${cleanTarget} actively responds to RPC Endpoint Mapper queries on TCP port 135, allowing remote attackers to enumerate registered RPC interfaces, UUIDs, and system endpoints.`,
      manualFix: 'Restrict access to TCP port 135 using Windows Defender Firewall to authorized management hosts only.',
      powershellCommands: [
        'New-NetFirewallRule -DisplayName "Restrict MSRPC Port 135" -Direction Inbound -LocalPort 135 -Protocol TCP -Action Block -RemoteAddress Any'
      ],
      cmdCommands: [
        'netsh advfirewall firewall add rule name="Block MSRPC Ingress" dir=in action=block protocol=TCP localport=135'
      ],
      verificationCommands: [
        'Test-NetConnection -ComputerName localhost -Port 135'
      ],
      rollbackSteps: [
        'Remove-NetFirewallRule -DisplayName "Restrict MSRPC Port 135"'
      ],
      rebootRequired: false,
      serviceRestartRequired: 'RpcSs (Remote Procedure Call service)',
      estimatedImpact: 'Zero Downtime - Blocks external RPC mapping while preserving internal RPC communications.',
      references: ['https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/firewall/configure-rpc-ports']
    };
  }

  // 5. REMOTE DESKTOP PROTOCOL (RDP)
  if (titleLower.includes('rdp') || titleLower.includes('remote desktop') || port === 3389) {
    return {
      detectedTargetPlatform: 'Windows Remote Desktop Services (RDP - TCP 3389)',
      rootCause: 'Remote Desktop Protocol (RDP) service is exposed over the network without Network Level Authentication (NLA) enforcement.',
      technicalExplanation: `Target host ${cleanTarget} listens for remote desktop connections on TCP port 3389. Directly accessible RDP ports are frequent targets for automated password spraying, credential brute-forcing, and remote desktop exploit attempts.`,
      manualFix: 'Enforce Network Level Authentication (NLA) for RDP connections, restrict port 3389 via firewall rules, or place RDP behind a VPN.',
      powershellCommands: [
        'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -Value 1',
        '(Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace "root\\cimv2\\terminalservices" -Filter "TerminalName=\'RDP-Tcp\'").SetUserAuthenticationRequired(1)'
      ],
      cmdCommands: [
        'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f'
      ],
      verificationCommands: [
        'Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name UserAuthentication'
      ],
      rollbackSteps: [
        'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -Value 0'
      ],
      rebootRequired: false,
      serviceRestartRequired: 'TermService (Remote Desktop Services)',
      estimatedImpact: 'Zero Downtime - Enforces pre-authentication before establishing graphic RDP sessions.',
      references: ['https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access']
    };
  }

  // 6. WINRM REMOTE MANAGEMENT
  if (titleLower.includes('winrm') || port === 5985 || port === 5986) {
    return {
      detectedTargetPlatform: 'Windows Remote Management (WinRM - TCP 5985/5986)',
      rootCause: 'WinRM HTTP/HTTPS listener exposed to untrusted network subnets.',
      technicalExplanation: `WinRM management service on ${cleanTarget}:${port} is accessible over the network. Exposed WinRM ports allow remote PowerShell remoting and administrative authentication probes.`,
      manualFix: 'Restrict WinRM ingress rules to authorized administrator IP addresses in Windows Firewall.',
      powershellCommands: [
        'Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -RemoteAddress "192.168.1.0/24"'
      ],
      verificationCommands: [
        'Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP"'
      ],
      rebootRequired: false,
      serviceRestartRequired: 'WinRM service',
      estimatedImpact: 'Zero Downtime - Restricts remote administrative access.',
      references: ['https://learn.microsoft.com/en-us/windows/win32/winrm/portal']
    };
  }

  // 7. HEARTBLEED / SSL TLS WEAK CIPHER / OPENSSL
  if (titleLower.includes('heartbleed') || titleLower.includes('ssl') || titleLower.includes('tls') || cveLower.includes('cve-2014-0160')) {
    return {
      detectedTargetPlatform: 'SSL/TLS Cryptographic Service (OpenSSL / IIS SSL)',
      rootCause: 'Outdated SSL/TLS library version or insecure cryptographic cipher suite enabled.',
      technicalExplanation: `The TLS service on ${cleanTarget}:${port} supports vulnerable OpenSSL heartbeat extensions or weak TLS 1.0/1.1 cipher suites, exposing encrypted process memory and session keys to remote extraction.`,
      manualFix: 'Upgrade OpenSSL library to latest stable version, disable legacy TLS 1.0/1.1 protocols, and enforce TLS 1.2/1.3 with AES-GCM cipher suites.',
      bashCommands: [
        'sudo apt-get update && sudo apt-get install --only-upgrade openssl libssl-dev',
        'sudo systemctl restart nginx || sudo systemctl restart apache2'
      ],
      powershellCommands: [
        'New-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server" -Name "Enabled" -Value 0 -PropertyType "DWord" -Force'
      ],
      verificationCommands: [
        `nmap -p ${port} --script ssl-enum-ciphers ${cleanTarget}`
      ],
      rebootRequired: false,
      serviceRestartRequired: 'Web server / SSL listener service restart required',
      estimatedImpact: 'Low - Brief web server worker process refresh.',
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2014-0160', 'https://www.openssl.org/news/secadv/20140407.txt']
    };
  }

  // 8. DIRECTORY TRAVERSAL / INFORMATION DISCLOSURE
  if (titleLower.includes('traversal') || titleLower.includes('disclosure') || titleLower.includes('sensitive') || cveLower.includes('cwe-22') || cveLower.includes('cwe-200')) {
    return {
      detectedTargetPlatform: 'Web Application & File Server System',
      rootCause: 'Application or web server lacks input parameter sanitization for path traversal sequences.',
      technicalExplanation: `Target application on ${cleanTarget}:${port} accepts unvalidated file path inputs containing dot-dot-slash (../) parameters, allowing remote actors to traverse outside the web directory and access internal configuration files.`,
      manualFix: 'Implement canonical path resolution (e.g. path.resolve() / realpath()) and whitelist valid file parameters in backend source code.',
      bashCommands: [
        '# Enforce strict input validation in application layer',
        '# Block ../ traversal patterns in web application firewall (WAF) or Nginx location block'
      ],
      configFilePath: '/etc/nginx/sites-available/default',
      configSnippets: [
        'if ($request_uri ~* "(\\.\\./|\\.\\.\\\\)") {',
        '    return 403;',
        '}'
      ],
      verificationCommands: [
        `curl -i "http://${cleanTarget}:${port}/?file=../../../../etc/passwd"`
      ],
      rebootRequired: false,
      serviceRestartRequired: 'Web application server reload',
      estimatedImpact: 'Zero Downtime - Application filter deployment.',
      references: ['https://owasp.org/www-community/attacks/Path_Traversal']
    };
  }

  // 9. MISSING HTTP SECURITY HEADERS
  if (titleLower.includes('header') || titleLower.includes('clickjacking') || titleLower.includes('hsts') || titleLower.includes('csp')) {
    return {
      detectedTargetPlatform: 'Web Server (Nginx / Apache / IIS)',
      rootCause: 'Web server is missing recommended HTTP security headers in response stream.',
      technicalExplanation: `The HTTP web service on ${cleanTarget}:${port} does not output security response headers (X-Frame-Options, X-Content-Type-Options, Content-Security-Policy), leaving browsers susceptible to clickjacking and MIME-sniffing.`,
      manualFix: 'Configure custom response headers in web server configuration files (nginx.conf, httpd.conf, or web.config).',
      bashCommands: [
        'sudo sed -i "/http {/a \\    add_header X-Frame-Options \\"SAMEORIGIN\\" always;\\n    add_header X-Content-Type-Options \\"nosniff\\" always;" /etc/nginx/nginx.conf',
        'sudo nginx -t && sudo systemctl reload nginx'
      ],
      powershellCommands: [
        'Import-Module WebAdministration',
        'Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/httpProtocol/customHeaders" -name "." -value @{name="X-Frame-Options";value="SAMEORIGIN"}'
      ],
      verificationCommands: [
        `curl -I http://${cleanTarget}:${port}/`
      ],
      rebootRequired: false,
      serviceRestartRequired: 'systemctl reload nginx / W3SVC',
      estimatedImpact: 'Zero Downtime - Hot reload without dropping active web sessions.',
      references: ['https://owasp.org/www-project-secure-headers/']
    };
  }

  // 10. NETWORK APPLIANCE / ROUTERS (Cisco, MikroTik, FortiGate)
  const isRouter = targetLower.endsWith('.1') || targetLower.includes('router') || targetLower.includes('gateway') || cleanTarget === '192.168.16.1' || targetLower.includes('cisco') || targetLower.includes('mikrotik') || targetLower.includes('forti');

  if (isRouter || serviceLower.includes('cisco') || serviceLower.includes('mikrotik') || serviceLower.includes('fortios') || bannerLower.includes('router')) {
    if (targetLower.includes('mikrotik') || bannerLower.includes('routeros')) {
      return {
        detectedTargetPlatform: 'MikroTik RouterOS v7.x (Network Appliance)',
        rootCause: 'Unencrypted RouterOS WWW web management interface enabled on port 80.',
        technicalExplanation: `Target ${cleanTarget} is running MikroTik RouterOS with the HTTP administration service enabled. Management traffic transmitted over unencrypted HTTP exposes credentials to network eavesdropping.`,
        manualFix: 'Disable unencrypted HTTP management in RouterOS IP Services menu and restrict WinBox / HTTPS administration to trusted management subnets.',
        cliCommands: [
          '/ip service set www disabled=yes',
          '/ip service set www-ssl port=443 disabled=no certificate=web-cert',
          '/ip service set winbox address=192.168.1.0/24'
        ],
        verificationCommands: [
          '/ip service print'
        ],
        rollbackSteps: [
          '/ip service set www disabled=no'
        ],
        rebootRequired: false,
        serviceRestartRequired: 'Immediate RouterOS IP service daemon apply',
        estimatedImpact: 'Low - Disables HTTP portal without dropping routed data plane traffic.',
        references: ['https://help.mikrotik.com/docs/display/ROS/Securing+Your+Router']
      };
    } else {
      return {
        detectedTargetPlatform: 'Cisco IOS / IOS-XE Router/Switch Network Appliance',
        rootCause: 'Unencrypted Cisco HTTP Server active on management interface.',
        technicalExplanation: `Target device ${cleanTarget} is running Cisco IOS HTTP server on port 80. Credentials and session tokens transmitted to this service can be intercepted via network sniffing attacks.`,
        manualFix: 'Disable Cisco HTTP server in global configuration mode and enable HTTPS secure server with active session protection.',
        cliCommands: [
          'configure terminal',
          'no ip http server',
          'ip http secure-server',
          'end',
          'write memory'
        ],
        verificationCommands: [
          'show ip http server status'
        ],
        rebootRequired: false,
        estimatedImpact: 'Low - Disables HTTP web server; SSH/Telnet management remains active.',
        references: ['https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/15-sy/https-15-sy-book.html']
      };
    }
  }

  // 11. GENERAL DYNAMIC FALLBACK MATCHING SPECIFIC VULNERABILITY TITLE & SEVERITY
  return {
    detectedTargetPlatform: `${service.toUpperCase()} Service on ${cleanTarget}`,
    rootCause: `Discovered vulnerability flaw '${vulnTitle || 'Security Vulnerability'}' on port ${port}.`,
    technicalExplanation: `Security assessment probe detected ${vulnTitle || 'vulnerable configuration'} on host ${cleanTarget}:${port}. Evidence: ${evidence || 'Service banner disclosed unpatched software version or unauthenticated endpoint.'}`,
    manualFix: `Review service configuration for ${service} on target ${cleanTarget}, apply latest vendor security patches, and enforce restrictive access control rules.`,
    bashCommands: [
      `# Inspect listening service configuration on port ${port}`,
      `sudo netstat -tlpn | grep :${port} || sudo ss -tlpn | grep :${port}`
    ],
    powershellCommands: [
      `Get-NetTCPConnection -LocalPort ${port} | Select-Object LocalAddress, LocalPort, State, OwningProcess`
    ],
    verificationCommands: [
      `nmap -sV -p ${port} ${cleanTarget}`
    ],
    rebootRequired: false,
    estimatedImpact: 'Low - Standard security configuration update.',
    references: cveId ? [`https://nvd.nist.gov/vuln/detail/${cveId}`] : ['https://nvd.nist.gov/']
  };
}

