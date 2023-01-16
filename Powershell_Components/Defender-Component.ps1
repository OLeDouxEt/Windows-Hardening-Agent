# This will be used to scan the default folders for each user on the system.
$QuickScanRoot= "C:\Users"

Function Confirm-DefendStatus {
    $overallStats = Get-MpComputerStatus
    
}

<# Might move this to another file
Function Confirm-DefenderHealth {
    Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational"
}
#>

<# .DESCRIPTION 
This function is meant to start a quick scan on any items folder user a user's folder such as
documents, downloads, or pictures. It will loop over the folders in the "Users" directory and skip over
any default folders to only scan actual user folders. The function will return a list of items scanned which
can be used in other functions.
#>
Function Start-liteScan {
    param(
        [string]$Folder
    )
    $userDirs = Get-ChildItem -Path $Folder
    $scanStart = @()
    # This will loop over all the user folders and start a quick scan of all the default folders
    # within the user's folder. However, it will not scan any of the folders in the "Public" or
    # "defaultuser0" folder.
    for ($i=0;$i -lt $userDirs.Count;$i++) {
        $isFolder = Test-Path $userDirs[$i].FullName -PathType Container
        # Skipping no user, deafult folders.
        if(($userDirs[$i].Name -eq "defaultuser0") -or ($userDirs[$i].Name -eq "Public") -or ($userDirs[$i].Name -eq "Default")){
            continue
        # Only searching for items that are folders under the "Users" Dir
        }elseif($isFolder){
            $userPath = $Folder + "\" + $userDirs[$i]
            $userSubDirs = Get-ChildItem -Path $userPath
            for($j=0;$j -lt $userSubDirs.Count;$j++){
                $targetPath = $userPath + "\" + $userSubDirs[$j]
                try{
                    Start-MpScan -ScanPath $targetPath -ScanType CustomScan
                    $scanStart += "Started scan on: $targetPath"
                # Attempting to run an offline scan if previous scan failed
                }catch{
                    Start-MpWDOScan 
                }finally{
                    $scanStart += "Unable to scan on: $targetPath"
                }
            }
        }
    }
    return $scanStart
}

$results = Start-liteScan -Folder $QuickScanRoot