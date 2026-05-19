<#
.SYNOPSIS
    Collects share and NTFS permissions of SMB network shares.
.DESCRIPTION
    
.PARAMETER SystemList
    The list of fully qualified domain systems to collect.
.PARAMETER GroupMembers
    
.PARAMETER Computers
    
.PARAMETER SearchBase
    The top level distinguished name path to use for computer object searching.
.PARAMETER Server
    The server to use for the target domain.
.PARAMETER CimSession

.PARAMETER LimitCollection
    
.EXAMPLE
    .\Get-ShareAndNtfsPermissions.ps1
    
.EXAMPLE
    .\Get-ShareAndNtfsPermissions.ps1 -SystemList (Get-Content systems.txt)
    This command attempts to pull all system names (recommend FQDN) listed in the systems.txt file.  It performs no Active Directory discovery lookups.
.NOTES
    Version 0.04
    Author: Sam Pursglove
    Last modified: 19 May 2026
#>

[CmdletBinding(DefaultParameterSetName='List')]
param (
    [Parameter(ParameterSetName='List', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Enter the list of fully qualified domain name systems (e.g. svr1.domain.com,svr2.domain.com).')]
    [Parameter(ParameterSetName='ListCIM', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Enter the list of fully qualified domain name systems (e.g. svr1.domain.com,svr2.domain.com).')]
    [string[]]$SystemList = '',

    [Parameter(ParameterSetName='Group', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Enter the group name of computer objects to enumerate.')]
    [Parameter(ParameterSetName='GroupCIM', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Enter the group name of computer objects to enumerate.')]
    [string[]]$GroupMembers = '',

    [Parameter(ParameterSetName='Computers', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Query all computer objects based on a distinguised name search base path.')]
    [Parameter(ParameterSetName='ComputersCIM', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Query all computer objects based on a distinguised name search base path.')]
    [switch]$Computers,

    [Parameter(ParameterSetName='Computers', Mandatory=$True, HelpMessage='Domain searchbase')]
    [Parameter(ParameterSetName='ComputersCIM', Mandatory=$True, HelpMessage='Domain searchbase')]
    [string]$SearchBase = '',

    [Parameter(ParameterSetName='Group', Mandatory=$False, HelpMessage='Target domain')]
    [Parameter(ParameterSetName='GroupCIM', Mandatory=$False, HelpMessage='Target domain')]
    [Parameter(ParameterSetName='Computers', Mandatory=$False, HelpMessage='Target domain')]
    [Parameter(ParameterSetName='ComputersCIM', Mandatory=$False, HelpMessage='Target domain')]
    [string]$Server = '',

    [Parameter(ParameterSetName='ListCIM',Mandatory=$True, HelpMessage='Run remote collection using a CIM session instead of PowerShell remoting.')]
    [Parameter(ParameterSetName='GroupCIM',Mandatory=$True, HelpMessage='Run remote collection using a CIM session instead of PowerShell remoting.')]
    [Parameter(ParameterSetName='ComputersCIM',Mandatory=$True, HelpMessage='Run remote collection using a CIM session instead of PowerShell remoting.')]
    [switch]$CimSession,

    [Parameter(Mandatory=$False, HelpMessage='Select share or NTFS permission collection only.')]
    [ValidateSet('ShareOnly','NtfsOnly')]
    [string]$LimitCollection
)


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
            [pscustomobject]@{
                PSComputerName       = $($path.PSComputerName)
                Name                 = $($path.Name)
                AccessControlType    = $($path.AccessControlType)
                AccessRight          = $($path.AccessRight)
                Path                 = $($Share.Path)
                Description          = $($Share.Description)
                ShareType            = $($Share.ShareType)
                ShareState           = $($Share.ShareState)
                EncryptData          = $($Share.EncryptData)
                CurrentUsers         = $($Share.CurrentUsers)
                FolderEnumerationMode= $($Share.FolderEnumerationMode)
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
                    [pscustomobject]@{
                        AccessDenied     = $true
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
                    $computer = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
                    $currentShare = $_.Name
                    "\\$computer\$currentShare" | Get-Acl -ErrorAction Stop
                
                # Maintain a record of a SMB share even if permissions read access is denied
                } catch [UnauthorizedAccessException] {
                    [pscustomobject]@{
                        AccessDenied     = $true
                        PSComputerName   = $computer
                        Path             = $currentShare
                    }  
                } 
            }
    }

    # Output each unique NTFS permission record
    foreach($access in $accesses) {

        # Confirm the object type is not AccessControl.FileSecurity from the Get-Acl cmdlet
        if($access.GetType().Name -ne 'PSCustomObject') {
            foreach($permission in ($access.Access)) {
         
                if($permission.FileSystemRights -match "[-0-9]+") {                  
                    $fileSystemRights = ($accessMask.Keys | Where-Object {$permission.FileSystemRights.Value__ -band $_ } | ForEach-Object { $accessMask.($_) } ) -join ', '
                } else {
                    $fileSystemRights = $permission.FileSystemRights
                }

                [pscustomobject]@{
                    PSComputerName   = ($access.Path -replace 'Microsoft.PowerShell.Core\\FileSystem::\\\\','').Split('\')[0]
                    Path             = ($access.Path -replace 'Microsoft.PowerShell.Core\\FileSystem::\\\\','').Split('\')[1]
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
            [pscustomobject]@{
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


# Converts the distinguised name format (e.g., CN=computer,OU=corporate,DC=domain,DC=com)
# to the FQDN version (e.g., computer.domain.com).  Can handle the first CN entry and one 
# or more DC entries.
function Convert-DistinguishedNameToFQDN {
    param($distinguishedNameList)

    foreach($dn in $distinguishedNameList) {
        $hostname = (
            [regex]::Matches($dn, '(?i)CN=([^,]+)') |
            Select-Object -Last 1
        ).Groups[1].Value

        $domain = (
            [regex]::Matches($dn, '(?i)DC=([^,]+)') |
            ForEach-Object { $_.Groups[1].Value }
        ) -join '.'

        ("$hostname.$domain").ToLower()
    }
}


if($SystemList) {
    $systems = $SystemList
} elseif($GroupMembers) {
    
    $params = @{
        Identity = $($GroupMembers)
        Properties = 'Member'
    }

    if($Server) {
        $params['Server'] = $Server
    }

    $distinguisedNames = (Get-ADGroup @params).Member
    $systems = Convert-DistinguishedNameToFQDN $distinguisedNames
} elseif($Computers) {
    #temp
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
    $sessions = New-PSSession -ComputerName $systems -SessionOption (New-PSSessionOption -NoMachineProfile)
}


# Run SMB share permissions collection
if($LimitCollection -ne 'NtfsOnly') {
    if($CimSession) {
        $outShare = Get-SmbSharePermissions $shares
    } else {
        $outShare = Invoke-Command -Session $sessions -ScriptBlock ${function:Get-SmbSharePermissions}
    }
    
    $outShare | 
        Select-Object PSComputerName,Name,AccessControlType,AccessRight,Path,Description,ShareType,ShareState,EncryptData,CurrentUsers,FolderEnumerationMode | 
        Export-Csv -Path SmbSharePermissions.csv -NoTypeInformation
}


# Run SMB NTFS permissions collection
if($LimitCollection -ne 'ShareOnly') {
    if($CimSession) {
        $outNtfs = Get-SmbNtfsPermissions $shares
    } else {
        $outNtfs = Invoke-Command -Session $sessions -ScriptBlock ${function:Get-SmbNtfsPermissions}
    }
          
    $outNtfs | 
        Select-Object PSComputerName,Path,Owner,Group,Identity,Access,Rights,IsInherited,InheritanceFlags,PropagationFlags |
        Export-Csv -Path NtfsSharePermissions.csv -NoTypeInformation
}

if(-not $CimSession) {
    $sessions | Remove-PSSession
}