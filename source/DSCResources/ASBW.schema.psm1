<#
    Following the principal of secure by default, this will require insecure settings to explicitly allowed.

    https://docs.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows
#>

Configuration ASBW
{
    param (
        [switch]
        $SkipAdministrativeTemplatesControlPanel,

        [switch]
        $SkipAdministrativeTemplatesNetwork,

        [switch]
        $SkipAdministrativeTemplatesSystem,

        [switch]
        $SkipSecurityOptionsAccounts,

        [switch]
        $SkipSecurityOptionsAudit,

        [switch]
        $SkipSecurityOptionsDevices,

        [switch]
        $SkipSecurityOptionsInteractiveLogon,

        [switch]
        $SkipSecurityOptionsMicrosoftNetworkClient,

        [switch]
        $SkipSecurityOptionsMicrosoftNetworkServer,

        [switch]
        $SkipSecurityOptionsNetworkAccess,

        [switch]
        $SkipSecurityOptionsNetworkSecurity,

        [switch]
        $SkipSecurityOptionsRecoveryconsole,

        [switch]
        $SkipSecurityOptionsShutdown,

        [switch]
        $SkipSecurityOptionsSystemobjects,

        [switch]
        $SkipSecurityOptionsSystemsettings,

        [switch]
        $SkipSecurityOptionsUserAccountControl,

        [switch]
        $SkipSecuritySettingsAccountPolicies,

        [switch]
        $SkipSystemAuditPoliciesAccountLogon,

        [switch]
        $SkipSystemAuditPoliciesAccountManagement,

        [switch]
        $SkipSystemAuditPoliciesDetailedTracking,

        [switch]
        $SkipSystemAuditPoliciesLogonLogoff,

        [switch]
        $SkipSystemAuditPoliciesObjectAccess,

        [switch]
        $SkipSystemAuditPoliciesPolicyChange,

        [switch]
        $SkipSystemAuditPoliciesPrivilegeUse,

        [switch]
        $SkipSystemAuditPoliciesSystem,

        [switch]
        $SkipUserRightsAssignment,

        [switch]
        $SkipWindowsComponents,

        [switch]
        $SkipWindowsFirewallProperties
    )

    # Import the needed DSC resources


    # Administrative Templates - Control Panel
    if ( -not $SkipAdministrativeTemplatesControlPanel )
    {
        # AZ-WIN-00168 - Allow Input Personalization
        # Description: This policy enables the automatic learning component of input personalization that includes
        # speech, inking, and typing. Automatic learning enables the collection of speech and handwriting patterns,
        # typing history, contacts, and recent calendar information. It is required for the use of Cortana. Some 
        # of this collected information may be stored on the user's OneDrive, in the case of inking and typing; 
        # some of the information will be uploaded to Microsoft to personalize speech. 
        # The recommended state for this setting is: Disabled.
        Registry 'AllowInputPersonalization' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization'
            ValueName  = 'AllowInputPersonalization'
            ValueType  = 'DWord'
            ValueData  = '1'
            Force      = $true
        }

        # CCE-38347-1 - Prevent enabling lock screen camera
        # Description: Disables the lock screen camera toggle switch in PC Settings and prevents a camera from 
        # being invoked on the lock screen. By default, users can enable invocation of an available camera on the
        # lock screen. If you enable this setting, users will no longer be able to enable or disable lock screen 
        # camera access in PC Settings, and the camera cannot be invoked on the lock screen.
        Registry 'NoLockScreenCamera' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueName  = 'NoLockScreenCamera'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }
        
        # CCE-38348-9 - Prevent enabling lock screen slide show
        # Description: Disables the lock screen slide show settings in PC Settings and prevents a slide show from 
        # playing on the lock screen. By default, users can enable a slide show that will run after they lock the 
        # machine. If you enable this setting, users will no longer be able to modify slide show settings in PC 
        # Settings, and no slide show will ever start.
        Registry 'NoLockScreenSlideshow' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueName  = 'NoLockScreenSlideshow'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }
    }

    # Administrative Templates - Network
    if ( -not $SkipAdministrativeTemplatesNetwork )
    {
        # AZ-WIN-00171 - Enable insecure guest logons
        # Description: This policy setting determines if the SMB client will allow insecure guest logons to an 
        # SMB server.  The recommended state for this setting is: Disabled.
        Registry 'AllowInsecureGuestAuth' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueName  = 'AllowInsecureGuestAuth'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-38338-0 - Minimize the number of simultaneous connections to the Internet or a Windows Domain
        # Description: This policy setting prevents computers from connecting to both a domain based network and 
        # a non-domain based network at the same time. The recommended state for this setting is: Enabled.
        Registry 'fMinimizeConnections' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueName  = 'fMinimizeConnections'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-38002-2 - Prohibit installation and configuration of Network Bridge on your DNS domain network
        # Description: You can use this procedure to control user's ability to install and configure a network 
        # bridge. The recommended state for this setting is: Enabled.
        Registry 'NC_AllowNetBridge_NLA' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            ValueName  = 'NC_AllowNetBridge_NLA'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }
        
        # AZ-WIN-00172 - Prohibit use of Internet Connection Sharing on your DNS domain network
        # Description: Although this "legacy" setting traditionally applied to the use of Internet Connection 
        # Sharing (ICS) in Windows 2000, Windows XP & Server 2003, this setting now freshly applies to the Mobile 
        # Hotspot feature in Windows 10 & Server 2016. The recommended state for this setting is: Enabled.
        Registry 'NC_ShowSharedAccessUI' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            ValueName  = 'NC_ShowSharedAccessUI'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }
        
        # AZ-WIN-00145 - Turn off multicast name resolution
        # Description: LLMNR is a secondary name resolution protocol. With LLMNR, queries are sent using multicast 
        # over a local network link on a single subnet from a client computer to another client computer on the 
        # same subnet that also has LLMNR enabled. LLMNR does not require a DNS server or DNS client 
        # configuration, and provides name resolution in scenarios in which conventional DNS name resolution is 
        # not possible. The recommended state for this setting is: Enabled.
        Registry 'EnableMulticast' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            ValueName  = 'EnableMulticast'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }
    }

    # Administrative Templates - System
    if ( -not $SkipAdministrativeTemplatesSystem )
    {
        # AZ-WIN-00138 - Block user from showing account details on sign-in
        # Description: This policy prevents the user from showing account details (email address or user name) on 
        # the sign-in screen. If you enable this policy setting, the user cannot choose to show account details on 
        # the sign-in screen. If you disable or do not configure this policy setting, the user may choose to show 
        # account details on the sign-in screen.
        Registry 'BlockUserFromShowingAccountDetailsOnSignin' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System'
            ValueName  = 'BlockUserFromShowingAccountDetailsOnSignin'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-37912-3 - Boot-Start Driver Initialization Policy
        # Description: This policy setting allows you to specify which boot-start drivers are initialized based on 
        # a classification determined by an Early Launch Antimalware boot-start driver. The Early Launch 
        # Antimalware boot-start driver can return the following classifications for each boot-start driver: 
        # - Good: The driver has been signed and has not been tampered with.
        # - Bad: The driver has been identified as malware. It is recommended that you do not allow known bad 
        #   drivers to be initialized.
        # - Bad, but required for boot: The driver has been identified as malware, but the computer cannot 
        #   successfully boot without loading this driver.
        # - Unknown: This driver has not been attested to by your malware detection application and has not been 
        #   classified by the Early Launch Antimalware boot-start driver. If you enable this policy setting you 
        #   will be able to choose which boot-start drivers to initialize the next time the computer is started. 
        # If you disable or do not configure this policy setting, the boot start drivers determined to be Good, 
        # Unknown or Bad but Boot Critical are initialized and the initialization of drivers determined to be Bad 
        # is skipped. If your malware detection application does not include an Early Launch Antimalware 
        # boot-start driver or if your Early Launch Antimalware boot-start driver has been disabled, this setting 
        # has no effect and all boot-start drivers are initialized.
        Registry 'DriverLoadPolicy' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            ValueName  = 'DriverLoadPolicy'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-36388-7 - Configure Offer Remote Assistance
        # Description: This policy setting allows you to turn on or turn off Offer (Unsolicited) Remote Assistance 
        # on this computer. Help desk and support personnel will not be able to proactively offer assistance, 
        # although they can still respond to user assistance requests. The recommended state for this setting is: 
        # Disabled.
        Registry 'fAllowUnsolicited' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'fAllowUnsolicited'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-37281-3 - Configure Solicited Remote Assistance
        # Description: This policy setting allows you to turn on or turn off Solicited (Ask for) Remote Assistance 
        # on this computer. The recommended state for this setting is: Disabled.
        Registry 'fAllowToGetHelp' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName  = 'fAllowToGetHelp'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-38353-9 - Do not display network selection UI
        # Description: This policy setting allows you to control whether anyone can interact with available 
        # networks UI on the logon screen. If you enable this policy setting, the PC's network connectivity state 
        # cannot be changed without signing into Windows. If you disable or don't configure this policy setting, 
        # any user can disconnect the PC from the network or can connect the PC to other available networks 
        # without signing into Windows.
        Registry 'DontDisplayNetworkSelectionUI' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName  = 'DontDisplayNetworkSelectionUI'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-37346-4 - Enable RPC Endpoint Mapper Client Authentication
        # Description: This policy setting controls whether RPC clients authenticate with the Endpoint Mapper 
        # Service when the call they are making contains authentication information. The Endpoint Mapper Service 
        # on computers running Windows NT4 (all service packs) cannot process authentication information supplied 
        # in this manner. If you disable this policy setting, RPC clients will not authenticate to the Endpoint 
        # Mapper Service, but they will be able to communicate with the Endpoint Mapper Service on Windows NT4 
        # Server. If you enable this policy setting, RPC clients will authenticate to the Endpoint Mapper Service 
        # for calls that contain authentication information. Clients making such calls will not be able to 
        # communicate with the Windows NT4 Server Endpoint Mapper Service. If you do not configure this policy 
        # setting, it remains disabled. RPC clients will not authenticate to the Endpoint Mapper Service, but they 
        # will be able to communicate with the Windows NT4 Server Endpoint Mapper Service. 
        # Note: This policy will not be applied until the system is rebooted.
        Registry 'EnableAuthEpResolution' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            ValueName  = 'EnableAuthEpResolution'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-37843-0 - Enable Windows NTP Client
        # Description: This policy setting specifies whether the Windows NTP Client is enabled. Enabling the 
        # Windows NTP Client allows your computer to synchronize its computer clock with other NTP servers. You 
        # might want to disable this service if you decide to use a third-party time provider. The recommended 
        # state for this setting is: Enabled.
        Registry 'NtpClientEnabled' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient'
            ValueName  = 'Enabled'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # AZ-WIN-00170 - Ensure 'Continue experiences on this device' is set to 'Disabled'
        # Description: This policy setting determines whether the Windows device is allowed to participate in 
        # cross-device experiences (continue experiences). The recommended state for this setting is: Disabled.
        Registry 'EnableCdp' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName  = 'EnableCdp'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }
        
        # CCE-36925-6 - Include command line in process creation events
        # Description: This policy setting determines what information is logged in security audit events when a 
        # new process has been created. This setting only applies when the Audit Process Creation policy is 
        # enabled. If you enable this policy setting the command line information for every process will be logged 
        # in plain text in the security event log as part of the Audit Process Creation event 4688, "a new process 
        # has been created," on the workstations and servers on which this policy setting is applied. If you 
        # disable or do not configure this policy setting, the process's command line information will not be 
        # included in Audit Process Creation events. Default: Not configured Note: When this policy setting is 
        # enabled, any user with access to read the security events will be able to read the command line 
        # arguments for any successfully created process. Command line arguments can contain sensitive or private 
        # information such as passwords or user data.
        Registry 'ProcessCreationIncludeCmdLine_Enabled' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            ValueName  = 'ProcessCreationIncludeCmdLine_Enabled'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-35893-7 - Turn off app notifications on the lock screen
        # Description: This policy setting allows you to prevent app notifications from appearing on the lock 
        # screen. The recommended state for this setting is: Enabled.
        Registry 'DisableLockScreenAppNotifications' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName  = 'DisableLockScreenAppNotifications'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-36625-2 - Turn off downloading of print drivers over HTTP
        # Description: This policy setting controls whether the computer can download print driver packages over 
        # HTTP. To set up HTTP printing, printer drivers that are not available in the standard operating system 
        # installation might need to be downloaded over HTTP. The recommended state for this setting is: Enabled.
        Registry 'DisableWebPnPDownload' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
            ValueName  = 'DisableWebPnPDownload'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }
        
        # CCE-37163-3 - Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com
        # Description: This policy setting specifies whether the Internet Connection Wizard can connect to 
        # Microsoft to download a list of Internet Service Providers (ISPs). The recommended state for this 
        # setting is: Enabled.
        Registry 'ExitOnMSICW' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard'
            ValueName  = 'ExitOnMSICW'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-37528-7 - Turn on convenience PIN sign-in
        # Description: This policy setting allows you to control whether a domain user can sign in using a 
        # convenience PIN. In Windows 10, convenience PIN was replaced with Passport, which has stronger security 
        # properties. To configure Passport for domain users, use the policies under Computer configuration\
        # Administrative Templates\Windows Components\Microsoft Passport for Work. 
        # Note: The user's domain password will be cached in the system vault when using this feature. The 
        # recommended state for this setting is: Disabled.
        Registry 'AllowDomainPINLogon' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueName  = 'AllowDomainPINLogon'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }
    }

    # Security Options - Accounts
    if ( -not $SkipSecurityOptionsAccounts )
    {
        # CCE-37432-2 - Accounts: Guest account status
        # Description: This policy setting determines whether the Guest account is enabled or disabled. The Guest 
        # account allows unauthenticated network users to gain access to the system. The recommended state for 
        # this setting is: Disabled. Note: This setting will have no impact when applied to the domain controller 
        # organizational unit via group policy because domain controllers have no local account database. It can 
        # be configured at the domain level via group policy, similar to account lockout and password policy 
        # settings.
Key Path: [System Access]EnableGuestAccount
Maybe Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions\Accounts_EnableGuestAccountStatus_LastWrite

        # CCE-37615-2 - Accounts: Limit local account use of blank passwords to console logon only
        # Description: This policy setting determines whether local accounts that are not password protected can 
        # be used to log on from locations other than the physical computer console. If you enable this policy 
        # setting, local accounts that have blank passwords will not be able to log on to the network from remote 
        # client computers. Such accounts will only be able to log on at the keyboard of the computer. The 
        # recommended state for this setting is: Enabled.
        Registry 'LimitBlankPasswordUse' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName  = 'LimitBlankPasswordUse'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }
    }

    # Security Options - Audit
    if ( -not $SkipSecurityOptionsAudit )
    {
        # CCE-37850-5 - Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit 
        # policy category settings
        # Description: This policy setting allows administrators to enable the more precise auditing capabilities 
        # present in Windows Vista. The Audit Policy settings available in Windows Server 2003 Active Directory do not 
        # yet contain settings for managing the new auditing subcategories. To properly apply the auditing policies 
        # prescribed in this baseline, the Audit: Force audit policy subcategory settings (Windows Vista or later) to 
        # override audit policy category settings setting needs to be configured to Enabled.
        Registry 'SCENoApplyLegacyAuditPolicy' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\'
            ValueName  = 'SCENoApplyLegacyAuditPolicy'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-35907-5 - Audit: Shut down system immediately if unable to log security audits
        # Description: This policy setting determines whether the system shuts down if it is unable to log Security 
        # events. It is a requirement for Trusted Computer System Evaluation Criteria (TCSEC)-C2 and Common Criteria 
        # certification to prevent auditable events from occurring if the audit system is unable to log them. 
        # Microsoft has chosen to meet this requirement by halting the system and displaying a stop message if the 
        # auditing system experiences a failure. When this policy setting is enabled, the system will be shut down if 
        # a security audit cannot be logged for any reason. If the Audit: Shut down system immediately if unable to 
        # log security audits setting is enabled, unplanned system failures can occur. The administrative burden can 
        # be significant, especially if you also configure the Retention method for the Security log to Do not 
        # overwrite events (clear log manually). This configuration causes a repudiation threat (a backup operator 
        # could deny that they backed up or restored data) to become a denial of service (DoS) vulnerability, because 
        # a server could be forced to shut down if it is overwhelmed with logon events and other security events that 
        # are written to the Security log. Also, because the shutdown is not graceful, it is possible that irreparable 
        # damage to the operating system, applications, or data could result. Although the NTFS file system guarantees 
        # its integrity when an ungraceful computer shutdown occurs, it cannot guarantee that every data file for 
        # every application will still be in a usable form when the computer restarts. The recommended state for this 
        # setting is: Disabled.
        Registry 'CrashOnAuditFail' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\'
            ValueName  = 'CrashOnAuditFail'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }
    }

    # Security Options - Devices
    if ( -not $SkipSecurityOptionsAudit )
    {
        # AZ-WIN-00120 - Devices: Allow undock without having to log on
        # Description: This policy setting determines whether a portable computer can be undocked if the user does 
        # not log on to the system. Enable this policy setting to eliminate a Logon requirement and allow use of 
        # an external hardware eject button to undock the computer. If you disable this policy setting, a user must 
        # log on and have been assigned the Remove computer from docking station user right to undock the computer.
        Registry 'UndockWithoutLogon' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName  = 'UndockWithoutLogon'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-37701-0 - Devices: Allowed to format and eject removable media
        # Description: This policy setting determines who is allowed to format and eject removable media. You can 
        # use this policy setting to prevent unauthorized users from removing data on one computer to access it on 
        # another computer on which they have local administrator privileges.
        Registry 'AllocateDASD' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            ValueName  = 'AllocateDASD'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        #  CCE-37942-0 - Devices: Prevent users from installing printer drivers
        # Description: For a computer to print to a shared printer, the driver for that shared printer must be 
        # installed on the local computer. This security setting determines who is allowed to install a printer 
        # driver as part of connecting to a shared printer. The recommended state for this setting is: Enabled. 
        # Note: This setting does not affect the ability to add a local printer. This setting does not affect 
        # Administrators.
        Registry 'AddPrinterDrivers' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'
            ValueName  = 'AddPrinterDrivers'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }
    }

    # Security Options - Interactive Logon
    if ( -not $SkipSecurityOptionsInteractiveLogon )
    {
        # CCE-36056-0 - Interactive logon: Do not display last user name
        # Description: This policy setting determines whether the account name of the last user to log on to the 
        # client computers in your organization will be displayed in each computer's respective Windows logon 
        # screen. Enable this policy setting to prevent intruders from collecting account names visually from the 
        # screens of desktop or laptop computers in your organization. The recommended state for this setting is: 
        # Enabled.
        Registry 'DontDisplayLastUserName' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName  = 'DontDisplayLastUserName'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-37637-6 - Interactive logon: Do not require CTRL+ALT+DEL
        # Description: This policy setting determines whether users must press CTRL+ALT+DEL before they log on. 
        # The recommended state for this setting is: Disabled.
        Registry 'DisableCAD' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName  = 'DisableCAD'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }
    }

    # Security Options - Microsoft Network Client
    if ( -not $SkipSecurityOptionsMicrosoftNetworkClient )
    {
        # CCE-36325-9 - Microsoft network client: Digitally sign communications (always)
        # Description: This policy setting determines whether packet signing is required by the SMB client 
        # component. Note: When Windows Vista-based computers have this policy setting enabled and they connect to 
        # file or print shares on remote servers, it is important that the setting is synchronized with its 
        # companion setting, Microsoft network server: Digitally sign communications (always), on those servers. 
        # For more information about these settings, see the "Microsoft network client and server: Digitally sign 
        # communications (four related settings)" section in Chapter 5 of the Threats and Countermeasures guide. 
        # The recommended state for this setting is: 'Enabled'.
        Registry 'RequireSecuritySignature' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
            ValueName  = 'RequireSecuritySignature'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-36269-9 - Microsoft network client: Digitally sign communications (if server agrees)
        # Description: This policy setting determines whether the SMB client will attempt to negotiate SMB packet 
        # signing. Note: Enabling this policy setting on SMB clients on your network makes them fully effective 
        # for packet signing with all clients and servers in your environment. The recommended state for this 
        # setting is: Enabled.
        Registry 'EnableSecuritySignature' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
            ValueName  = 'EnableSecuritySignature'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-37863-8 - Microsoft network client: Send unencrypted password to third-party SMB servers
        # Description: This policy setting determines whether the SMB redirector will send plaintext passwords 
        # during authentication to third-party SMB servers that do not support password encryption. It is 
        # recommended that you disable this policy setting unless there is a strong business case to enable it. If 
        # this policy setting is enabled, unencrypted passwords will be allowed across the network. The 
        # recommended state for this setting is: 'Disabled'.
        Registry 'EnablePlainTextPassword' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
            ValueName  = 'EnablePlainTextPassword'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-38046-9 - Microsoft network server: Amount of idle time required before suspending session
        # Description: This policy setting allows you to specify the amount of continuous idle time that must pass 
        # in an SMB session before the session is suspended because of inactivity. Administrators can use this 
        # policy setting to control when a computer suspends an inactive SMB session. If client activity resumes, 
        # the session is automatically reestablished. A value of 0 appears to allow sessions to persist 
        # indefinitely. The maximum value is 99999, which is over 69 days; in effect, this value disables the 
        # setting. The recommended state for this setting is: 15 or fewer minute(s), but not 0.
        Key Path: SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect
        Registry 'EnablePlainTextPassword' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
            ValueName  = 'EnablePlainTextPassword'
            ValueType  = 'DWord'
            # We should have a way to customize this value from 1 to 15
            ValueData  = '5'
            Force      = $true
        }

        # CCE-37864-6 - Microsoft network server: Digitally sign communications (always)
        # Description: This policy setting determines whether packet signing is required by the SMB server 
        # component. Enable this policy setting in a mixed environment to prevent downstream clients from using 
        # the workstation as a network server. The recommended state for this setting is: Enabled.
        Registry 'RequireSecuritySignature' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
            ValueName  = 'RequireSecuritySignature'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }

        # CCE-35988-5 - Microsoft network server: Digitally sign communications (if client agrees)
        # Description: This policy setting determines whether the SMB server will negotiate SMB packet signing 
        # with clients that request it. If no signing request comes from the client, a connection will be allowed 
        # without a signature if the Microsoft network server: Digitally sign communications (always) setting is 
        # not enabled. Note: Enable this policy setting on SMB clients on your network to make them fully 
        # effective for packet signing with all clients and servers in your environment. The recommended state for 
        # this setting is: Enabled.
        Registry 'EnableSecuritySignature' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
            ValueName  = 'EnableSecuritySignature'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }
        
        # CCE-37972-7 - Microsoft network server: Disconnect clients when logon hours expire
        # Description: This security setting determines whether to disconnect users who are connected to the local 
        # computer outside their user account's valid logon hours. This setting affects the Server Message Block 
        # (SMB) component. If you enable this policy setting you should also enable Network security: Force logoff 
        # when logon hours expire (Rule 2.3.11.6). If your organization configures logon hours for users, this 
        # policy setting is necessary to ensure they are effective. The recommended state for this setting is: 
        # Enabled.
        Registry 'EnableForcedLogoff' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
            ValueName  = 'EnableForcedLogoff'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }
    }

    # Security Options - Microsoft Network Server
    if ( -not $SkipSecurityOptionsMicrosoftNetworkServer )
    {
        # AZ-WIN-00175 -  Disable SMB v1 server
        # Description: Disabling this setting disables server-side processing of the SMBv1 protocol. (Recommended.) 
        # Enabling this setting enables server-side processing of the SMBv1 protocol. (Default.) Changes to this 
        # setting require a reboot to take effect. For more information, see https://support.microsoft.com/kb/2696547
        Registry 'SMB1' {
            Ensure     = 'Present'
            Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            ValueName  = 'SMB1'
            ValueType  = 'DWord'
            ValueData  = '0'
            Force      = $true
        }
    }

# Security Options - Network Access


# Security Options - Network Security


# Security Options - Recovery console


# Security Options - Shutdown


# Security Options - System objects


# Security Options - System settings


# Security Options - User Account Control


# Security Settings - Account Policies


# System Audit Policies - Account Logon


# System Audit Policies - Account Management


# System Audit Policies - Detailed Tracking


# System Audit Policies - Logon-Logoff


# System Audit Policies - Object Access


# System Audit Policies - Policy Change


# System Audit Policies - Privilege Use


# System Audit Policies - System


# User Rights Assignment


# Windows Components


# Windows Firewall Properties 
}