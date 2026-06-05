<#
.SYNOPSIS
    Collect share and NTFS permissions of SMB network shares.
.DESCRIPTION
    Script to collection SMB share and NTFS permissions for remoted systems.  Privileged access is required for the targets.  By default collection is performed using PowerShell remoting but an option exists to alternatively collect using CIM sessions.  Targets can be designated using three different options.  1) User defined list of FQDN system names 2) An AD security group of AD computer objects 3) A domain of all computer objects or sub-organizational unit (OU).
.PARAMETER SystemList
    Query target AD computer object permissions based on a user defined list of fully qualified domain name (FQDN) systems.
.PARAMETER Group
    Query target AD computer object permissions based on the membership of a security group.
.PARAMETER Computers
    Query target AD computer object permissions based on a domain or sub-organizational units.
.PARAMETER SearchBase
    The top level distinguished name path to use for computer object searching, can include sub-organizational units.
.PARAMETER Server
    The server to use for the target domain.
.PARAMETER CimSession
    Alternate remote collection option (instead of PowerShell remoting) using the Get-SmbShare cmdlet with CIM sessions.
.PARAMETER LimitCollection
    Option to collection either share or NTFS permissions, but not both.
.PARAMETER AltSmartCardCred
    An option to use alternate smart card credentials for PowerShell remoting sessions.    
.EXAMPLE
    .\Get-ShareAndNtfsPermissions.ps1 -SystemList (Get-Content systems.txt)
    Attempts to query all system SMB share and NTFS permissions (recommend FQDN) listed in the systems.txt file.  It performs no Active Directory discovery lookups.
.EXAMPLE
    .\Get-ShareAndNtfsPermissions.ps1 -SystemList (Get-Content systems.txt) -CimSession
    Attempts to query all system SMB share and NTFS permissions (recommend FQDN) listed in the systems.txt file using CIM sessions instead of PowerShell remoting.  It performs no Active Directory discovery lookups.
.EXAMPLE
    .\Get-ShareAndNtfsPermissions.ps1 -GroupMembers 'Servers Group' -Server domain.com
    Attempts to query all AD computer object SMB share and NTFS permissions that are members of the security group 'Servers Group' and in the domain.com domain.
.EXAMPLE
    .\Get-ShareAndNtfsPermissions.ps1 -GroupMembers 'Servers Group' -Server domain.com -AltSmartCardCred
    Attempts to query all AD computer object SMB share and NTFS permissions that are members of the security group 'Servers Group' and in the domain.com domain.  Will prompt the user to use alternative smartcard certificate/PIN that is different than the current user context and will be used for remote session connectivity.
.EXAMPLE
    .\Get-ShareAndNtfsPermissions.ps1 -Computers -SearchBase 'ou=servers,dc=domain,dc=com'
    Attempts to query all AD computer object SMB share and NTFS permissions that are in the 'servers' OU.
.EXAMPLE
    .\Get-ShareAndNtfsPermissions.ps1 -Computers -SearchBase 'ou=servers,dc=domain,dc=com' -LimitCollection NtfsOnly
    Attempts to query all AD computer object SMB NTFS permissions only that are in the 'servers' OU.
.NOTES
    Version 0.08
    Author: Sam Pursglove
    Last modified: 05 June 2026
#>

[CmdletBinding(DefaultParameterSetName='List')]
param (
    [Parameter(ParameterSetName='List', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Enter the list of fully qualified domain name systems (e.g. svr1.domain.com,svr2.domain.com).')]
    [Parameter(ParameterSetName='ListCIM', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Enter the list of fully qualified domain name systems (e.g. svr1.domain.com,svr2.domain.com).')]
    [string[]]$SystemList = '',

    [Parameter(ParameterSetName='Group', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Enter the group name of computer objects to enumerate.')]
    [Parameter(ParameterSetName='GroupCIM', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Enter the group name of computer objects to enumerate.')]
    [string]$Group = '',

    [Parameter(ParameterSetName='Computers', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Query all computer objects based on a distinguished name search base path.')]
    [Parameter(ParameterSetName='ComputersCIM', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Query all computer objects based on a distinguished name search base path.')]
    [switch]$Computers,

    [Parameter(ParameterSetName='Computers', Mandatory=$True, HelpMessage='Domain searchbase')]
    [Parameter(ParameterSetName='ComputersCIM', Mandatory=$True, HelpMessage='Domain searchbase')]
    [string]$SearchBase = '',

    [Parameter(ParameterSetName='Group', Mandatory=$False, HelpMessage='Target domain')]
    [Parameter(ParameterSetName='GroupCIM', Mandatory=$False, HelpMessage='Target domain')]
    [Parameter(ParameterSetName='Computers', Mandatory=$False, HelpMessage='Target domain')]
    [Parameter(ParameterSetName='ComputersCIM', Mandatory=$False, HelpMessage='Target domain')]
    [string]$Server = '',

    [Parameter(ParameterSetName='List', Mandatory=$False, HelpMessage='Use alternate, non-default smart card credentials')]
    [Parameter(ParameterSetName='Group', Mandatory=$False, HelpMessage='Use alternate, non-default smart card credentials')]
    [Parameter(ParameterSetName='Computers', Mandatory=$False, HelpMessage='Use alternate, non-default smart card credentials')]
    [Switch]$AltSmartCardCred,

    [Parameter(ParameterSetName='ListCIM',Mandatory=$True, HelpMessage='Run remote collection using a CIM session instead of PowerShell remoting.')]
    [Parameter(ParameterSetName='GroupCIM',Mandatory=$True, HelpMessage='Run remote collection using a CIM session instead of PowerShell remoting.')]
    [Parameter(ParameterSetName='ComputersCIM',Mandatory=$True, HelpMessage='Run remote collection using a CIM session instead of PowerShell remoting.')]
    [switch]$CimSession,

    [Parameter(Mandatory=$False, HelpMessage='Select share or NTFS permission collection only.')]
    [ValidateSet('ShareOnly','NtfsOnly')]
    [string]$LimitCollection
)


Function Get-SmartCardCred{
<#
.SYNOPSIS
Get certificate credentials from the user's certificate store.

.DESCRIPTION
Returns a PSCredential object of the user's selected certificate.

.EXAMPLE
Get-SmartCardCred
UserName                                           Password
--------                                           --------
@@BVkEYkWiqJgd2d9xz3-5BiHs1cAN System.Security.SecureString

.EXAMPLE
$Cred = Get-SmartCardCred

.OUTPUTS
[System.Management.Automation.PSCredential]

.NOTES
Author: Joshua Chase
Last Modified: 01 August 2018
C# code used from https://github.com/bongiovimatthew-microsoft/pscredentialWithCert
#>
    [cmdletbinding()]
    param()

    $SmartCardCode = @"
    // Copyright (c) Microsoft Corporation. All rights reserved.
    // Licensed under the MIT License.

    using System;
    using System.Management.Automation;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Cryptography.X509Certificates;

    namespace SmartCardLogon{

        static class NativeMethods
        {

            public enum CRED_MARSHAL_TYPE
            {
                CertCredential = 1,
                UsernameTargetCredential
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct CERT_CREDENTIAL_INFO
            {
                public uint cbSize;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
                public byte[] rgbHashOfCert;
            }

            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern bool CredMarshalCredential(
                CRED_MARSHAL_TYPE CredType,
                IntPtr Credential,
                out IntPtr MarshaledCredential
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool CredFree([In] IntPtr buffer);

        }

        public class Certificate
        {

            public static PSCredential MarshalFlow(string thumbprint, SecureString pin)
            {
                //
                // Set up the data struct
                //
                NativeMethods.CERT_CREDENTIAL_INFO certInfo = new NativeMethods.CERT_CREDENTIAL_INFO();
                certInfo.cbSize = (uint)Marshal.SizeOf(typeof(NativeMethods.CERT_CREDENTIAL_INFO));

                //
                // Locate the certificate in the certificate store 
                //
                X509Certificate2 certCredential = new X509Certificate2();
                X509Store userMyStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                userMyStore.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certsReturned = userMyStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                userMyStore.Close();

                if (certsReturned.Count == 0)
                {
                    throw new Exception("Unable to find the specified certificate.");
                }

                //
                // Marshal the certificate 
                //
                certCredential = certsReturned[0];
                certInfo.rgbHashOfCert = certCredential.GetCertHash();
                int size = Marshal.SizeOf(certInfo);
                IntPtr pCertInfo = Marshal.AllocHGlobal(size);
                Marshal.StructureToPtr(certInfo, pCertInfo, false);
                IntPtr marshaledCredential = IntPtr.Zero;
                bool result = NativeMethods.CredMarshalCredential(NativeMethods.CRED_MARSHAL_TYPE.CertCredential, pCertInfo, out marshaledCredential);

                string certBlobForUsername = null;
                PSCredential psCreds = null;

                if (result)
                {
                    certBlobForUsername = Marshal.PtrToStringUni(marshaledCredential);
                    psCreds = new PSCredential(certBlobForUsername, pin);
                }

                Marshal.FreeHGlobal(pCertInfo);
                if (marshaledCredential != IntPtr.Zero)
                {
                    NativeMethods.CredFree(marshaledCredential);
                }
            
                return psCreds;
            }
        }
    }
"@

    Add-Type -TypeDefinition $SmartCardCode -Language CSharp
    Add-Type -AssemblyName System.Security

    $ValidCerts = [System.Security.Cryptography.X509Certificates.X509Certificate2[]](Get-ChildItem 'Cert:\CurrentUser\My')
    $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2UI]::SelectFromCollection($ValidCerts, 'Personal Certificate Store', 'Choose a certificate', 0)

    if ($Cert) {
        $Pin = Read-Host "Enter your certificate PIN: " -AsSecureString
    } else {
        exit
    }

    [SmartCardLogon.Certificate]::MarshalFlow($Cert.Thumbprint, $Pin)
}


# Get share permissions
function Get-SmbSharePermissions {
    param([Parameter(Mandatory=$False)]$shares)

    # Get SMB shares locally if PowerShell remoting is used (not CIM sessions) via Invoke-Command
    if(-not $shares) {
        $shares = Get-SmbShare
    }

    # Collect individual SMB share permissions
    foreach($share in $shares) {
        $sharePath  = $share | Get-SmbShareAccess

        foreach($path in $sharePath) {
            # output as a hashtable and not a PSCustomObject to avoid Constrained Language Mode issues
            @{
                PSComputerName       = $($share.PSComputerName)
                Name                 = $($path.Name)
                AccountName          = $($path.AccountName)
                AccessControlType    = $($path.AccessControlType)
                AccessRight          = $($path.AccessRight)
                Path                 = $($share.Path)
                Description          = $($share.Description)
                ShareType            = $($share.ShareType)
                ShareState           = $($share.ShareState)
                EncryptData          = $($share.EncryptData)
                CurrentUsers         = $($share.CurrentUsers)
                FolderEnumerationMode= $($share.FolderEnumerationMode)
            }
        }
    }
}


# Get NTFS permissions
function Get-SmbNtfsPermissions {
    param([Parameter(Mandatory=$False)]$shares)

    # dictionary for access right translation
    $accessMask = [ordered]@{
        [int32]'0x80000000' = 'GenericRead'
        [int32]'0x40000000' = 'GenericWrite'
        [int32]'0x20000000' = 'GenericExecute'
        [int32]'0x10000000' = 'GenericAll'
        [int32]'0x02000000' = 'MaximumAllowed'
        [int32]'0x01000000' = 'AccessSystemSecurity'
        [int32]'0x00100000' = 'Synchronize'
        [int32]'0x00080000' = 'WriteOwner'
        [int32]'0x00040000' = 'WriteDAC'
        [int32]'0x00020000' = 'ReadControl'
        [int32]'0x00010000' = 'Delete'
        [int32]'0x00000100' = 'WriteAttributes'
        [int32]'0x00000080' = 'ReadAttributes'
        [int32]'0x00000040' = 'DeleteChild'
        [int32]'0x00000020' = 'Execute/Traverse'
        [int32]'0x00000010' = 'WriteExtendedAttributes'
        [int32]'0x00000008' = 'ReadExtendedAttributes'
        [int32]'0x00000004' = 'AppendData/AddSubdirectory'
        [int32]'0x00000002' = 'WriteData/AddFile'
        [int32]'0x00000001' = 'ReadData/ListDirectory'
    }

    # Collect NTFS permissions if CIM sessions were used
    if($shares) {
        $accesses = $shares | 
            Where-Object {$_.ShareType -eq 'FileSystemDirectory'} | 
            ForEach-Object {
                try {
                    $computer = $_.PSComputerName
                    $currentShare = $_.Name
                    "\\$computer\$currentShare" | Get-Acl -ErrorAction Stop
                } catch [UnauthorizedAccessException] {
                    New-Object PSObject -Property @{
                        PSComputerName   = $computer
                        Path             = $currentShare
                    }
                } 
            }
    # Collect NTFS permissions if PowerShell remoting is used
    } else {
        $accesses = Get-SmbShare | 
            Where-Object {$_.ShareType -eq 'FileSystemDirectory'} | 
            ForEach-Object {
                try {
                    $computer = (Resolve-DnsName -Name $env:COMPUTERNAME -Type A -ErrorAction SilentlyContinue)[0].Name
                    if(-not $computer) {
                        $computer = $env:COMPUTERNAME
                    }
                    
                    $currentShare = $_.Name
                    "\\$computer\$currentShare" | Get-Acl -ErrorAction Stop
                
                # Maintain a record of a SMB share even if permissions read access is denied
                } catch [UnauthorizedAccessException] {
                    New-Object PSObject -Property @{
                        PSComputerName   = $computer
                        Path             = $currentShare
                    }
                } 
            }
    }

    # Output each unique NTFS permission record
    foreach($access in $accesses) {

        # Confirm the object type is AccessControl.FileSecurity from the Get-Acl cmdlet
        if($access -is [System.Security.AccessControl.DirectorySecurity]) {
            foreach($permission in ($access.Access)) {
         
                if($permission.FileSystemRights -match "[-0-9]+") {                  
                    $fileSystemRights = ($accessMask.Keys | Where-Object {$permission.FileSystemRights.Value__ -band $_ } | ForEach-Object { $accessMask.($_) } ) -join ', '
                } else {
                    $fileSystemRights = $permission.FileSystemRights
                }

                $cleanPath = $access.Path -replace 'Microsoft.PowerShell.Core\\FileSystem::\\\\',''
                $pathElements = $cleanPath -split '\\'

                @{
                    PSComputerName   = $pathElements[0]
                    Path             = $pathElements[1]
                    Owner            = $access.Owner
                    Group            = $access.Group
                    Identity         = $permission.IdentityReference
                    Access           = $permission.AccessControlType
                    Rights           = $fileSystemRights            
                    IsInherited      = $permission.IsInherited
                    InheritanceFlags = $permission.InheritanceFlags
                    PropagationFlags = $permission.PropagationFlags
                }
            }

        # Output a record of any SMB share even if the permissions read access was denied
        } else {       
            @{
                PSComputerName   = $access.PSComputerName
                Path             = $access.Path
                Owner            = 'Access denied'
                Group            = 'Access denied'
                Identity         = 'Access denied'
                Access           = 'Access denied'
                Rights           = 'Access denied'
                IsInherited      = 'Access denied'
                InheritanceFlags = 'Access denied'
                PropagationFlags = 'Access denied'
            }
        }
    }
}


# target systems are determined by 1 of 3 options: predefined user provived list,
# computer members of a security group, or computer objects in a domain/OU.
if($SystemList) {
    # target systems defined by use provided list, must be FQDNs
    $systems = $SystemList
} elseif($Group) {
    # target systems determined based on an AD security group of computer objects
    $paramsGroup = @{
        Identity = $($Group)
        Properties = 'Member'
    }

    $paramsComp = @{
        Properties = 'OperatingSystem'
    }

    if($Server) {
        $paramsGroup['Server'] = $Server
        $paramsComp['Server'] = $Server
    }

    # get all the group members
    $distinguishedNames = (Get-ADGroup @paramsGroup).Member
    
    # Get the DNSHostName foreach group member (returns a distinguished name version from the group)
    [System.Collections.ArrayList]$systems = @()

    foreach($name in $distinguishedNames) {
        $paramsComp['Identity'] = $name
        $systems.Add((Get-ADComputer @paramsComp | Where-Object {$_.OperatingSystem -like "Windows*"}).DNSHostName) | Out-Null
    }
} elseif($Computers) {
    # target systems determined based on a domain or organizational unit
    $params = @{
        Filter = '*'
        SearchBase = $SearchBase
        Properties = 'OperatingSystem'
    }

    if($Server) {
        $params['Server'] = $Server
    }

    $systems = (Get-ADComputer @params | Where-Object {$_.OperatingSystem -like "Windows*"}).DNSHostName
}


# Ensure systems are avaialable to launch PS remoting or CIM sessions
if(($systems | Measure-Object).Count -eq 0) {
    Write-Output 'No systems discovered. Exiting.'
    exit
}


# Default is to run collection using PowerShell remoting
if($CimSession) {
    
    # Run collection via CIM sessions
    $shares = foreach ($system in $systems) {
        try {
            Get-SmbShare -CimSession $system -IncludeHidden
        } catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
            Write-Output "SMB access denied: $($system)"
        }
    }
} else {

    # Run collection via PowerShell remoting
    $paramsSess = @{
        ComputerName = $systems
        SessionOption = (New-PSSessionOption -NoMachineProfile)
    }

    if($AltSmartCardCred) {
        $paramsSess['Credential'] = (Get-SmartCardCred)
    }

    $sessions = New-PSSession @paramsSess
}


# Run SMB share permissions collection
if($LimitCollection -ne 'NtfsOnly') {
    if($CimSession) {
        $outShare = Get-SmbSharePermissions $shares
    } else {
        $outShare = Invoke-Command -Session $sessions -ScriptBlock ${function:Get-SmbSharePermissions}
    }
    
    if($outShare) {
        $outShare | 
            # This is used to avoid Constrained Language Mode issues
            Select-Object @{Name='PSComputerName'; Expression={$_.PSComputerName}},
                          @{Name='Name'; Expression={$_.Name}},
                          @{Name='AccountName'; Expression={$_.AccountName}},
                          @{Name='AccessControlType'; Expression={$_.AccessControlType}},
                          @{Name='AccessRight'; Expression={$_.AccessRight}},
                          @{Name='Path'; Expression={$_.Path}},
                          @{Name='Description'; Expression={$_.Description}},
                          @{Name='ShareType'; Expression={$_.ShareType}},
                          @{Name='ShareState'; Expression={$_.ShareState}},
                          @{Name='EncryptData'; Expression={$_.EncryptData}},
                          @{Name='CurrentUsers'; Expression={$_.CurrentUsers}},
                          @{Name='FolderEnumerationMode'; Expression={$_.FolderEnumerationMode}} | 
            Export-Csv -Path SmbSharePermissions.csv -NoTypeInformation
    }
}


# Run SMB NTFS permissions collection
if($LimitCollection -ne 'ShareOnly') {
    if($CimSession) {
        $outNtfs = Get-SmbNtfsPermissions $shares
    } else {
        $outNtfs = Invoke-Command -Session $sessions -ScriptBlock ${function:Get-SmbNtfsPermissions}
    }

    if($outNtfs) {          
        $outNtfs | 
            Select-Object @{Name='PSComputerName'; Expression={$_.PSComputerName}},
                          @{Name='Path'; Expression={$_.Path}},
                          @{Name='Owner'; Expression={$_.Owner}},
                          @{Name='Group'; Expression={$_.Group}},
                          @{Name='Identity'; Expression={$_.Identity}},
                          @{Name='Access'; Expression={$_.Access}},
                          @{Name='Rights'; Expression={$_.Rights}},
                          @{Name='IsInherited'; Expression={$_.IsInherited}},
                          @{Name='InheritanceFlags'; Expression={$_.InheritanceFlags}},
                          @{Name='PropagationFlags'; Expression={$_.PropagationFlags}} |
            #Select-Object PSComputerName,Path,Owner,Group,Identity,Access,Rights,IsInherited,InheritanceFlags,PropagationFlags |
            Export-Csv -Path NtfsSharePermissions.csv -NoTypeInformation
    }
}

if(-not $CimSession) {
    $sessions | Remove-PSSession
}