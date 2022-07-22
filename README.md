# Azure-Security-Baseline-Windows-DSC
A DSC composite module to secure a Windows server to the Azure Security Baseline

# Overview
This is to use DSC to make a Windows server compliant with the Windows security baseline found at https://docs.microsoft.com/en-us/azure/governance/policy/samples/guest-configuration-baseline-windows.

To help in rolling out the template to existing installs, sections of the baseline can be skipped until it is safe to change those settings on the server.