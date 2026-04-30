$systemList = 'OSAKAKOBEFS012.connect.sbu','OSAKAKOBEPRT12.connect.sbu'

# SMB
$shares = foreach ($system in $systemList) {
    Get-SmbShare -CimSession $system -IncludeHidden
}

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

$smbOut | Export-Csv -Path smbSharePermissions.csv -NoTypeInformation


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

# NTFS
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

$ntfsOut | Export-Csv -Path ntfsSharePermissions.csv -NoTypeInformation