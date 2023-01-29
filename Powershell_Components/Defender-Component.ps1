# - May add deep scan function with bootsector scanning and offline scan

# This will be used to scan the default folders for each user on the system.
$QuickScanRoot = "C:\Users"
$CMDScanRoot = "C:\Program Files\Windows Defender"

Function Confirm-DefendStatus {
    $DefStatus = @{
        "StoppedServs" = @();
        "RunningServs" = @();
        "DisabledSets" = @();
        "EnabledSets" = @()
    }
    # First Checking security services
    $secServs = Get-Service Windefend, SecurityHealthService, wscsvc
    #Write-Output $secServs
    for($i=0;$i -lt $secServs.Count;$i++){
        if($secServs[$i].Status -ne "Running"){
            Write-Warning "$($secServs[$i].DisplayName) is not running!"
            $DefStatus.StoppedServs += $secServs[$i].DisplayName 
        }else{
            $DefStatus.RunningServs += $secServs[$i].DisplayName
        }
    }
    # Then checking the status of the windows defender security settings
    $defSets = Get-MpComputerStatus | Select-Object -Property Antivirusenabled,AMServiceEnabled,AntispywareEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled
    foreach($setting in $defSets.PSObject.Properties){
        if($setting.Value -eq $false){
            Write-Warning "$($setting.Name) is disabled!"
            $DefStatus.DisabledSets += $setting.Name
        }else{
            $DefStatus.EnabledSets += $setting.Name
        }
    }
    return $DefStatus
}

# Update virus singatures function
Function Update-VirusSigs {

    
}

# VVV ---------- Scanning Functions Below ---------- VVV 

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
                # Attempting to start a scan using the command line tool if previous attempt failed.
                # Then informing the user if trageted scan fails.
                }catch{
                    try{
                        $scannerPath = "$CMDScanRoot\MpCmdRun.exe"
                        Start-Process -FilePath $scannerPath -ArgumentList "-Scan", "-ScanType 3", "-File $Folder"
                    }catch{
                        $scanStart += "Unable to scan on: $targetPath"
                    }
                }
            }
        }
    }
    return $scanStart
}

Function Start-QuickScan {
    $quickStatus = $false
    try {
        Start-MpScan -ScanType QuickScan
        $quickStatus = $true
    }
    catch {
        try{
            $scannerPath = "$CMDScanRoot\MpCmdRun.exe"
            Start-Process -FilePath $scannerPath -ArgumentList "-Scan", "-ScanType 1"
            $quickStatus = $true
        }catch{
            $quickStatus = $false
        }
    }
    return $quickStatus
}

Function Start-FullScan {
    $fullStatus = $false
    try{
        Start-MpScan -ScanType FullScan
        $fullStatus = $true
    }catch{
        try{
            $scannerPath = "$CMDScanRoot\MpCmdRun.exe"
            Start-Process -FilePath $scannerPath -ArgumentList "-Scan", "-ScanType 2"
            $fullStatus = $true
        }catch{
            $fullStatus = $false
        }
    }
    return $fullStatus
}

Function Search-Threats {

}

#Function 

Confirm-DefendStatus
#$results = Start-liteScan -Folder $QuickScanRoot