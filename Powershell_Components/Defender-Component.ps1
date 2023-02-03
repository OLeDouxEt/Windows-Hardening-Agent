<#.SYNOPSIS
    This file includes functions to manage and monitor Windows Defender that are meant
    to be envoked by the agent.
#>

# This will be used to scan the default folders for each user on the system.
$QuickScanRoot = "C:\Users"
$CMDScanRoot = "C:\Program Files\Windows Defender"

<# .DESCRIPTION 
    This function will check to see if services related to Windows Defender are running properly. It will also check if
    any security functions have been disabled using "Get-MpComputerStatus". All Information regarding the security services status
    and the security properties status will be return as a hashtable for the agent to use.
#>
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

<# .DESCRIPTION 
Update virus singatures function. Accepts an age limit parameter, measured in days, to determine
if the signatures need to be updated.
#>
Function Update-VirusSigs {
    Param (
        [int32]$Limit
    )
    $sigsUpdated = $false
    $allVersionData = Get-MpComputerStatus
    $lastUpdated = $allVersionData.AntivirusSignatureAge
    if($lastUpdated -gt $limit){
        try{    
            # Updating Antivirus Signatures
            Update-MpSignature
            $sigsUpdated = $true
        }catch{
            # Attempting to use "mpcmdrun" command-line tool as backup to update signatures
            try{
                $defenderPath = "C:\Program Files\Windows Defender\"
                Set-Location $defenderPath
                Start-Process .\MpCmdRun.exe -ArgumentList "-SignatureUpdate"
                $sigsUpdated = $true
            }catch{
                $sigsUpdated = $false
            }
        }
    }else{
        # If signatures are not older than the specified age limit, the function returns true
        # to indicate the sifnatures are up to date.
        $sigsUpdated = $true
    }
    return $sigsUpdated
}

# VVV ---------- Scanning Functions Below ---------- VVV 

<# .DESCRIPTION 
This function is meant to start a quick scan on any items folder user a user's folder such as
documents, downloads, or pictures. It will loop over the folders in the "Users" directory and skip over
any default folders to only scan actual user folders. The function will return a list of items scanned which
can be used in other functions.
#>
Function Start-liteScan {
    Param(
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

# Just starts a quick scan. Will return if it succeeded or failed.
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

# Just starts a full scan. Will return if it succeeded or failed.
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

<# .DESCRIPTION 
This function checks with "Get-MpThreat" to see if there are any active threats and retrieves the IDs of those threats.
It will then use the active threat ID and information from "Get-MpThreatDetection" to return where the threats are located.
#>
Function Search-Threats {
    $threatOverview = Get-MpThreat
    $threatDetails = Get-MpThreatDetection
    $activeThreats = @{}
    $confirmedThreats = @()
    for($i=0;$i -lt $threatOverview.Count;$i++){
        if($threatOverview[$i].IsActive){
            $activeThreats[$threatOverview[$i].ThreatID] = 1
        }
    }
    # Cross referencing the threats found by using the "ThreatID" property from all the "threatDetails" 
    # objects as the key in "activeThreats" to confirm that the threat is active and gather more deatils about
    # it to return. 
    foreach($threat in $threatDetails){
        if($activeThreats[$threat.ThreatID]){
            $confirmedThreats += $threat.Resources
        }
    }
    return $confirmedThreats
}

# Very basic function to remove active threats on device. This will be expanded upon in phase 2.
Function Remove-Threats {
    $removedThreats = $false
    try{
        Remove-MpThreat
        $removedThreats = $true
    }catch{
        $removedThreats = $false
    }
    return $removedThreats
}
