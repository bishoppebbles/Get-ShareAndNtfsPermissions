<#
.SYNOPSIS
    Collects share and NTFS permissions of SMB network shares.
.DESCRIPTION
    
.PARAMETER OUName
    The specific OU name of interest.  Can be used to limit the collection scope in a domain environment.
.PARAMETER Migrated
    Switch to use if computer objects have migrated to a different domain.
.PARAMETER Region
    The specific target region.
.PARAMETER SearchBase
    The top level distinguished name path to use for computer object searching.
.PARAMETER Server
    The server to use for the target domain.
.PARAMETER SystemList
    The list of fully qualified domain systems to collect.  Note that this option does not export system data to the domain_computers.csv dataset as it is unavailable.
.EXAMPLE
    .\Get-ShareAndNtfsPermissions.ps1
    
.EXAMPLE
    .\Get-ShareAndNtfsPermissions.ps1 -SystemList (Get-Content systems.txt)
    This command attempts to pull all system names (recommend FQDN) listed in the systems.txt file.  It performs no Active Directory discovery lookups.
.NOTES
    Version 0.03
    Author: Sam Pursglove
    Last modified: 18 May 2026
#>

[CmdletBinding(DefaultParameterSetName='List')]
param (
    [Parameter(ParameterSetName='List', Mandatory=$True, ValueFromPipeline=$False, HelpMessage="Enter the list of fully qualified domain name systems (e.g. 'svr1.domain.com','svr2.domain.com')")]
    [Parameter(ParameterSetName='ListShareOnly', Mandatory=$True, ValueFromPipeline=$False, HelpMessage="Enter the list of fully qualified domain name systems (e.g. 'svr1.domain.com','svr2.domain.com')")]
    [Parameter(ParameterSetName='ListNtfsOnly', Mandatory=$True, ValueFromPipeline=$False, HelpMessage="Enter the list of fully qualified domain name systems (e.g. 'svr1.domain.com','svr2.domain.com')")]
    [string[]]$SystemList = '',

    [Parameter(ParameterSetName='Group', Mandatory=$True, ValueFromPipeline=$False, HelpMessage="Enter the group name of computer objects to enumerate")]
    [Parameter(ParameterSetName='GroupShareOnly', Mandatory=$True, ValueFromPipeline=$False, HelpMessage="Enter the group name of computer objects to enumerate")]
    [Parameter(ParameterSetName='GroupNtfsOnly', Mandatory=$True, ValueFromPipeline=$False, HelpMessage="Enter the group name of computer objects to enumerate")]
    [string[]]$GroupMembers = '',

    [Parameter(ParameterSetName='Computers', Mandatory=$True, ValueFromPipeline=$False, HelpMessage="Query all computer objects based on a distinguised name search base")]
    [Parameter(ParameterSetName='ComputersShareOnly', Mandatory=$True, ValueFromPipeline=$False, HelpMessage="Query all computer objects based on a distinguised name search base")]
    [Parameter(ParameterSetName='ComputersNtfsOnly', Mandatory=$True, ValueFromPipeline=$False, HelpMessage="Query all computer objects based on a distinguised name search base")]
    [switch]$Computers,

    [Parameter(ParameterSetName='Computers', Mandatory=$True, HelpMessage='Domain searchbase')]
    [Parameter(ParameterSetName='ComputersShareOnly', Mandatory=$True, HelpMessage='Domain searchbase')]
    [Parameter(ParameterSetName='ComputersNtfsOnly', Mandatory=$True, HelpMessage='Domain searchbase')]
    [string]$SearchBase = '',

    [Parameter(ParameterSetName='Group', Mandatory=$False, HelpMessage='Target domain')]
    [Parameter(ParameterSetName='GroupShareOnly', Mandatory=$False, HelpMessage='Target domain')]
    [Parameter(ParameterSetName='GroupNtfsOnly', Mandatory=$False, HelpMessage='Target domain')]
    [Parameter(ParameterSetName='Computers', Mandatory=$False, HelpMessage='Target domain')]
    [Parameter(ParameterSetName='ComputersShareOnly', Mandatory=$False, HelpMessage='Target domain')]
    [Parameter(ParameterSetName='ComputersNtfsOnly', Mandatory=$False, HelpMessage='Target domain')]
    [string]$Server = '',

    [Parameter(ParameterSetName='ListShareOnly',Mandatory=$False, HelpMessage='Only collect the share permissions of SMB shares.')]
    [Parameter(ParameterSetName='GroupShareOnly',Mandatory=$False, HelpMessage='Only collect the share permissions of SMB shares.')]
    [Parameter(ParameterSetName='ComputersShareOnly',Mandatory=$False, HelpMessage='Only collect the share permissions of SMB shares.')]
    [switch]$SharePermissionsOnly,

    [Parameter(ParameterSetName='ListNtfsOnly',Mandatory=$False, HelpMessage='Only collect the NTFS permissions of SMB shares.')]
    [Parameter(ParameterSetName='GroupNtfsOnly',Mandatory=$False, HelpMessage='Only collect the NTFS permissions of SMB shares.')]
    [Parameter(ParameterSetName='ComputersNtfsOnly',Mandatory=$False, HelpMessage='Only collect the NTFS permissions of SMB shares.')]
    [switch]$NtfsPermissionsOnly
)



# Share permissions
function Get-SmbSharePermissions {
    param($shares)

    $smbOut = foreach($share in $shares) {
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

    $smbOut
}


# NTFS permissions
function Get-SmbNtfsPermissions {
    param($shares)

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

    $ntfsOut = foreach($access in $accesses) {
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

    $ntfsOut
}

# Get SMB shares
$shares = foreach ($system in $systemList) {
    try {
        Get-SmbShare -CimSession $system -IncludeHidden
    } catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
        Write-Output "SMB access denied: $($system)"
    }
}

if(-not $NtfsPermissionsOnly) {
    if($out = Get-SmbSharePermissions $shares) {
        $out | Export-Csv -Path SmbSharePermissions.csv -NoTypeInformation
    }
}

if(-not $SharePermissionsOnly) {
    if($out = Get-SmbNtfsPermissions $shares) {       
        $out | Export-Csv -Path NtfsSharePermissions.csv -NoTypeInformation
    }
}