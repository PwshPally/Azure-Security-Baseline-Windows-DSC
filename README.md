# Azure-Security-Baseline-Windows-DSC
A DSC composite module to secure a Windows server to the Azure Security Baseline

# Overview
This is to use DSC to make a Windows server compliant with the Windows security baseline found at https://docs.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows.

To help in rolling out the template to existing installs, sections of the baseline can be skipped until it is safe to change those settings on the server.

# Why use DSC?
There are other options to force the configuration of the VM.  However, for an envirnment that is already live there is a need to roll out the changes in a controlled manner.  This allows the settings, or a part of the settings to be applied in that controlled manner.

The policy can be applied while skipping all the settings to just one VM.  This puts you in a position to turn on just one section at a time.  Then as you turn on one section let it stay for say a week.  If you then know it's safe, turn it on for the other servers of the same type, and turn on the next section.  Or if you have a lot of VMs, consider using rings to roll it out.