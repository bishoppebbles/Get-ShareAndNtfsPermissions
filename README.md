# Get-ShareAndNtfsPermissions
Script to collect SMB share and NTFS permissions for remote systems. By default collection is performed using PowerShell remoting but an option exists to alternatively collect using CIM sessions.  This a rewrite of [Get-ServerSharePermissionsReport](https://github.com/bishoppebbles/Get-ServerSharePermissionsReport) that was a slightly modified version written by [VeeFu](https://github.com/VeeFu/SysAdminScripts/tree/master/SecurityReports). The original HTML output looks nice but working with the data for analysis purposes I think is a little cumbersome.  Now it’s all in CSV format.  There are some additions:

* It also collects SMB share permissions (the original was NTFS only).
* It’s faster and defaults to using PowerShell remoting.  Running as a CIM session is still an option too (though with WSMAN and not DCOM).
* Additional data fields for each collection set have been added.
* Includes a record of a share that exists but where NTFS permission read access is denied.

## Help
The script includes full PowerShell documentation including script usage examples and some options not discussed here (e.g., `-CimSession`, `-LimitCollection`, and `-AltSmartCardCred`).

  * `Get-Help .\Get-ShareAndNtfsPermissions.ps1`

## Usage Examples
The targeting of systems for collection is different than with `Get-ServerSharePermissionsReport`.  The original was based off a hostname wildcard search.  Now it’s not as rigid.  Collection can be more explicitly performed on server or workstation Active Directory computer objects with three different options to choose from.  You must have the proper privileges for your target systems, or this will not work.

1) **SystemList option**

    a) Provide a text file list of target hostnames (recommend the FQDN/DNSHostName version).  The text file `srvs.txt` would have a list of FQDN servers names (one per line) like `srv1.domain.com`, `srv2.domain.com`, and `srv3.domain.com`, etc.

      * `.\Get-ShareAndNtfsPermissions.ps1 -SystemList (Get-Content .\srvs.txt)`

2) **Group option**

    a) Provide an AD security group name that has target systems as member computer objects.

      * `.\Get-ShareAndNtfsPermissions.ps1 -Group 'Servers Group'`

    b) If you’re trying to run cross domain include the -Server option:

      * `.\Get-ShareAndNtfsPermissions.ps1 -Group 'Servers Group' -Server connect.sbu`

3) **Computers option**

    a) This is more traditional in terms of how the Active Directory cmdlets work by targeting a distinguished name path, which can include sub-organizational units (OUs).

      * `.\Get-ShareAndNtfsPermissions.ps1 -Computers -SearchBase ‘ou=servers,dc=domain,dc=com’`
