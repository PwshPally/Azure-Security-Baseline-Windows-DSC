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


# Administrative Templates - System


# Security Options - Accounts


# Security Options - Audit


# Security Options - Devices


# Security Options - Interactive Logon


# Security Options - Microsoft Network Client


# Security Options - Microsoft Network Server


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