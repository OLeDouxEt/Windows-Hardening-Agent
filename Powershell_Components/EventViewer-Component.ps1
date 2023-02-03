<#.SYNOPSIS
#>

<#.DESCRIPTION
    Function for searching through the event logs related to Windows Defender for targeted event IDs that could
    hinder Defender's ability to protect an endpoint. The events will be returned as a hashtable containing information
    about the event and when it occured.
#>
Function Trace-DefenderLogs {
    $DefCodeMap = @{
        1002 = @();
        5001 = @();
        5007 = @();
        5013 = @()
    }

    $allDefEvents = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational"
    for($i=0;$i -lt $allDefEvents.Count;$i++){
        if($DefCodeMap.ContainsKey($allDefEvents[$i].Id)){
            $DefCodeMap[$allDefEvents[$i].Id] += $allDefEvents[$i]
        }
    }
    Return $DefCodeMap
}

Function Trace-SecurtiyLogs {
    $SecCodeMap = @{
        4625 = @();
        4720 = @();
        4723 = @()
    }
    Get-WinEvent -ProviderName "Microsoft-Windows-Security-Auditing"
}