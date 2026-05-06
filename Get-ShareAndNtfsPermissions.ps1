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
    Version 0.02
    Author: Sam Pursglove
    Last modified: 05 May 2025
#>

[CmdletBinding(DefaultParameterSetName='Domain')]
param (
    [Parameter(ParameterSetName='Domain', Mandatory=$False, HelpMessage='Target OU name')]
    [Parameter(ParameterSetName='Migrated', Mandatory=$True, HelpMessage='Target OU name')]
    [string]$OUName = '',

    [Parameter(ParameterSetName='Migrated', Mandatory=$True, HelpMessage='Switch to change the search type for AD migrated systems')]
    [Switch]$Migrated,

    [Parameter(ParameterSetName='Migrated', Mandatory=$True, HelpMessage='Target region name')]
    [string]$Region = '',

    [Parameter(ParameterSetName='Domain', Mandatory=$False, HelpMessage='Domain searchbase')]
    [Parameter(ParameterSetName='Migrated', Mandatory=$True, HelpMessage='Domain searchbase')]
    [string]$SearchBase = '',

    [Parameter(ParameterSetName='Domain', Mandatory=$False, HelpMessage='Domain controller server')]
    [Parameter(ParameterSetName='Migrated', Mandatory=$True, HelpMessage='Domain controller server')]
    [string]$Server = '',

    [Parameter(ParameterSetName='List', Mandatory=$True, ValueFromPipeline=$False, HelpMessage="Enter the list of fully qualified domain name systems (e.g. 'svr1.domain.com','svr2.domain.com')")]
    [string[]]$SystemList = ''
)

# SMB shares
$shares = foreach ($system in $systemList) {
    Get-SmbShare -CimSession $system -IncludeHidden
}

# Share permissions
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

$smbOut | Export-Csv -Path SmbSharePermissions.csv -NoTypeInformation


# NTFS permissions
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
       "\\$($_.PSComputerName)\$($_.Name)" | Get-Acl
    }

$ntfsOut = foreach($access in $accesses) {
    
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
}

$ntfsOut | Export-Csv -Path NtfsSharePermissions.csv -NoTypeInformation