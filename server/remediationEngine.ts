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

  // 1. SERVICE EXISTENCE VERIFICATION GUARD
  // If port is 0 or service is empty/closed, no remediation is needed
  if (port === 0 || serviceLower.includes('closed') || serviceLower.includes('filtered')) {
    return {
      detectedTargetPlatform: 'Inactive / Closed Port',
      rootCause: 'Service port is not listening or is filtered by firewall rules.',
      technicalExplanation: `The target host ${cleanTarget} does not have an active service listening on the specified port (${port}).`,
      manualFix: 'No remediation required. The affected service is not installed or active on this target.',
      rebootRequired: false,
      estimatedImpact: 'None',
      references: ['https://nvd.nist.gov/']
    };
  }

  // 2. NETWORK APPLIANCE / ROUTER DETECTION (Cisco, MikroTik, FortiGate, Huawei, Ruijie, pfSense)
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
    } else if (targetLower.includes('forti') || bannerLower.includes('fortios')) {
      return {
        detectedTargetPlatform: 'Fortinet FortiGate Firewall (FortiOS 7.x)',
        rootCause: 'HTTP administrative access enabled on external or internal interface.',
        technicalExplanation: `FortiGate unit at ${cleanTarget} exposes HTTP admin portal on port ${port}.`,
        manualFix: 'Disable HTTP admin port in FortiOS system global settings and force HTTPS redirection.',
        cliCommands: [
          'config system global',
          'unset admin-port',
          'set admin-sport 443',
          'set admin-https-redirect enable',
          'end'
        ],
        verificationCommands: [
          'get system global | grep admin'
        ],
        rollbackSteps: [
          'config system global',
          'set admin-port 80',
          'end'
        ],
        rebootRequired: false,
        serviceRestartRequired: 'FortiOS administrative daemon reload',
        estimatedImpact: 'Low - Restricts web admin port without interrupting firewall sessions.',
        references: ['https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/330541/admin-http-https']
      };
    } else {
      // Default Cisco IOS / IOS-XE
      return {
        detectedTargetPlatform: 'Cisco IOS / IOS-XE Router/Switch Network Appliance',
        rootCause: 'Unencrypted Cisco HTTP Server active on management interface.',
        technicalExplanation: `Target device ${cleanTarget} is running Cisco IOS HTTP server on port 80. Credentials and session tokens transmitted to this service can be intercepted via network sniffing attacks.`,
        manualFix: 'Disable Cisco HTTP server in global configuration mode and enable HTTPS secure server with active session protection.',
        cliCommands: [
          'configure terminal',
          'no ip http server',
          'ip http secure-server',
          'ip http active-session-modules none',
          'end',
          'write memory'
        ],
        verificationCommands: [
          'show ip http server status',
          'show running-config | include ip http'
        ],
        rollbackSteps: [
          'configure terminal',
          'ip http server',
          'end',
          'write memory'
        ],
        rebootRequired: false,
        serviceRestartRequired: 'Immediate CLI active runtime apply',
        estimatedImpact: 'Low - Disables HTTP web server; SSH/Telnet/HTTPS management remains active.',
        references: ['https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/https/configuration/15-sy/https-15-sy-book.html']
      };
    }
  }

  // 3. WINDOWS SERVER / IIS DETECTION
  const isWindows = targetLower.includes('win') || targetLower.includes('iis') || serviceLower.includes('iis') || serviceLower.includes('microsoft-ds') || port === 445 || bannerLower.includes('microsoft');

  if (isWindows) {
    if (port === 80 || port === 443 || serviceLower.includes('http') || serviceLower.includes('iis')) {
      return {
        detectedTargetPlatform: 'Windows Server 2022 / IIS 10.0 Web Server',
        rootCause: 'IIS web server is missing security hardening HTTP headers (X-Frame-Options, X-Content-Type-Options, CSP).',
        technicalExplanation: `The IIS web service running on ${cleanTarget}:${port} does not include defensive response headers in HTTP replies, leaving client browsers vulnerable to clickjacking and MIME-type sniffing attacks.`,
        manualFix: 'Configure custom response headers in IIS Manager under HTTP Response Headers or directly in the system web.config XML file.',
        powershellCommands: [
          'Import-Module WebAdministration',
          'Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/httpProtocol/customHeaders" -name "." -value @{name="X-Frame-Options";value="SAMEORIGIN"}',
          'Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/httpProtocol/customHeaders" -name "." -value @{name="X-Content-Type-Options";value="nosniff"}',
          'Restart-Service W3SVC'
        ],
        cmdCommands: [
          'appcmd.exe set config /section:httpProtocol /+customHeaders.[name=\'X-Frame-Options\',value=\'SAMEORIGIN\']',
          'appcmd.exe set config /section:httpProtocol /+customHeaders.[name=\'X-Content-Type-Options\',value=\'nosniff\']',
          'iisreset /noforce'
        ],
        configFilePath: 'C:\\inetpub\\wwwroot\\web.config',
        configSnippets: [
          '<system.webServer>',
          '  <httpProtocol>',
          '    <customHeaders>',
          '      <add name="X-Frame-Options" value="SAMEORIGIN" />',
          '      <add name="X-Content-Type-Options" value="nosniff" />',
          '    </customHeaders>',
          '  </httpProtocol>',
          '</system.webServer>'
        ],
        verificationCommands: [
          `Invoke-WebRequest -Uri "http://${cleanTarget}:${port}" -Method Head | Select-Object -ExpandProperty Headers`
        ],
        rollbackSteps: [
          'appcmd.exe set config /section:httpProtocol /-customHeaders.[name=\'X-Frame-Options\']',
          'iisreset'
        ],
        rebootRequired: false,
        serviceRestartRequired: 'W3SVC (IIS Web Publishing Service)',
        estimatedImpact: 'Low - Brief IIS worker pool refresh (~1-2s).',
        references: ['https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httpprotocol/customheaders/']
      };
    } else {
      // General Windows SMB / Active Directory
      return {
        detectedTargetPlatform: 'Windows Server Operating System (Active Directory / SMB)',
        rootCause: 'Legacy SMBv1 protocol driver enabled or insecure system defaults.',
        technicalExplanation: `Target ${cleanTarget} has SMB file sharing active on port 445. Legacy protocol support creates exposure to WannaCry / EternalBlue exploit vectors.`,
        manualFix: 'Disable SMBv1 in Windows Server registry and PowerShell, then restart the LanmanServer service.',
        powershellCommands: [
          'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force',
          'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB1" -Type DWord -Value 0 -Force'
        ],
        cmdCommands: [
          'sc.exe config lanmanserver start= auto',
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
        serviceRestartRequired: 'LanmanServer / System reboot required for SMB kernel driver unload',
        estimatedImpact: 'Medium - System reboot required.',
        references: ['https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3']
      };
    }
  }

  // 4. LINUX DISTRIBUTIONS (Ubuntu, Debian, CentOS, RHEL, Rocky, Alpine)
  const isRhelOrCentOS = targetLower.includes('rhel') || targetLower.includes('centos') || targetLower.includes('rocky') || targetLower.includes('alma');

  if (isRhelOrCentOS) {
    // Enterprise Linux (dnf/yum)
    return {
      detectedTargetPlatform: 'Enterprise Linux (RHEL 9 / Rocky Linux / CentOS) - Apache httpd',
      rootCause: 'Web server missing defensive HTTP security response headers.',
      technicalExplanation: `The Apache httpd web server running on ${cleanTarget}:${port} does not output security headers in response stream.`,
      manualFix: 'Create a dedicated security configuration file in /etc/httpd/conf.d/ and test configuration with apachectl.',
      bashCommands: [
        'sudo dnf install -y httpd',
        'echo "Header always set X-Frame-Options \"SAMEORIGIN\"" | sudo tee /etc/httpd/conf.d/security.conf',
        'echo "Header always set X-Content-Type-Options \"nosniff\"" | sudo tee -a /etc/httpd/conf.d/security.conf',
        'sudo apachectl configtest',
        'sudo systemctl reload httpd'
      ],
      configFilePath: '/etc/httpd/conf.d/security.conf',
      configSnippets: [
        'Header always set X-Frame-Options "SAMEORIGIN"',
        'Header always set X-Content-Type-Options "nosniff"',
        'Header always set Content-Security-Policy "default-src \'self\';"'
      ],
      verificationCommands: [
        `curl -I http://${cleanTarget}:${port}/`
      ],
      rollbackSteps: [
        'sudo rm /etc/httpd/conf.d/security.conf',
        'sudo systemctl reload httpd'
      ],
      rebootRequired: false,
      serviceRestartRequired: 'systemctl reload httpd',
      estimatedImpact: 'Zero Downtime - Hot reload without dropping active web sessions.',
      references: ['https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/deploying_web_servers/']
    };
  }

  // Default Linux (Ubuntu 22.04 / Debian LTS) - Nginx / Apache / SSH
  if (port === 22 || serviceLower.includes('ssh')) {
    return {
      detectedTargetPlatform: 'Linux (Ubuntu 22.04 LTS) - OpenSSH Service',
      rootCause: 'Insecure SSH daemon configuration allowing password authentication or root login.',
      technicalExplanation: `The OpenSSH service on ${cleanTarget}:22 allows password authentication, exposing the server to brute-force credential stuffing attacks.`,
      manualFix: 'Disable root SSH login and password authentication in /etc/ssh/sshd_config, then reload sshd.',
      bashCommands: [
        'sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak',
        'sudo sed -i "s/#PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config',
        'sudo sed -i "s/#PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config',
        'sudo sshd -t',
        'sudo systemctl reload sshd'
      ],
      configFilePath: '/etc/ssh/sshd_config',
      configSnippets: [
        'PermitRootLogin no',
        'PasswordAuthentication no',
        'X11Forwarding no',
        'MaxAuthTries 3'
      ],
      verificationCommands: [
        `ssh -o PreferredAuthentications=password root@${cleanTarget}`
      ],
      rollbackSteps: [
        'sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config',
        'sudo systemctl reload sshd'
      ],
      rebootRequired: false,
      serviceRestartRequired: 'systemctl reload sshd',
      estimatedImpact: 'Zero Downtime - Existing SSH connections remain uninterrupted.',
      references: ['https://ubuntu.com/server/docs/service-openssh']
    };
  }

  // Nginx on Ubuntu / Debian (Default Web Server Platform)
  return {
    detectedTargetPlatform: 'Linux (Ubuntu 22.04 LTS / Debian 12) - Nginx Web Server',
    rootCause: 'Nginx web server missing HTTP security headers (X-Frame-Options, X-Content-Type-Options, CSP).',
    technicalExplanation: `The active Nginx web server on host ${cleanTarget}:${port} is missing security hardening headers such as Content-Security-Policy and X-Frame-Options, exposing users to clickjacking and MIME sniffing.`,
    manualFix: 'Edit Nginx security configuration (/etc/nginx/nginx.conf), append missing HTTP security headers, verify configuration syntax with nginx -t, and reload service.',
    bashCommands: [
      'sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak',
      'sudo sed -i "/http {/a \\    add_header X-Frame-Options \\"SAMEORIGIN\\" always;\\n    add_header X-Content-Type-Options \\"nosniff\\" always;" /etc/nginx/nginx.conf',
      'sudo nginx -t',
      'sudo systemctl reload nginx'
    ],
    configFilePath: '/etc/nginx/nginx.conf',
    configSnippets: [
      'add_header X-Frame-Options "SAMEORIGIN" always;',
      'add_header X-Content-Type-Options "nosniff" always;',
      'add_header Content-Security-Policy "default-src \'self\';" always;'
    ],
    verificationCommands: [
      `curl -I http://${cleanTarget}:${port}/`
    ],
    rollbackSteps: [
      'sudo cp /etc/nginx/nginx.conf.bak /etc/nginx/nginx.conf',
      'sudo systemctl reload nginx'
    ],
    rebootRequired: false,
    serviceRestartRequired: 'systemctl reload nginx',
    estimatedImpact: 'Zero Downtime - Hot reload without dropping active web connections.',
    references: ['https://nginx.org/en/docs/http/ngx_http_headers_module.html', 'https://owasp.org/www-project-secure-headers/']
  };
}
