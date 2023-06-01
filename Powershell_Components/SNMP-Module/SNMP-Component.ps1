<#.DESCRIPTION
Function does what its name says. Will recursively loop over a PSCustomObject and extract the
property names and values to convert the object to a hashmap/hashtable. This is done so the data
will be eaiser to work with in other script functions
#>
Function Convert-JSONtoMap {
    param(
        $Data
    )
    $tempCon = @{}
    foreach ($prop in $Data.PSObject.Properties) {
        $tempCon[$prop.Name] = ""
        $type0 = $prop.Value.GetType()
        if($type0.Name -eq "PSCustomObject"){
            $tempCon[$prop.Name] = Convert-JSONtoMap -Data $prop.Value
        }else{
            $tempCon[$prop.Name] = $prop.Value
        }
    }
    Return $tempCon
}

<#.DESCRIPTION
This function is meant to pull in information about each network device and add it to a hashtable
so that other function can access that data to query the SNMP agent running on the target device.
A key is created for each device with its IP, Community string, and a hashtable of OIDs to access 
a specific property of the SNMP agent on that device. The data is returned as one big hashtable.
#>
Function Initialize-Devices {
    $dir = $PSScriptRoot
    $rawConfig = ""
    $configMap = ""
    try{
        $rawConfig = Get-Content "$dir/config.json" | ConvertFrom-Json -ErrorAction Stop
    }catch{
        $rawConfig = 0
    }
    $type0 = $rawConfig.GetType()
    # Will only try to data to map if it was successfully retrieved to avoid errors
    if($type0.Name -ne "PSCustomObject"){
        Return $rawConfig
    }
    $configMap = Convert-JSONtoMap $rawConfig
    # Need to add the network devices' OIDs to their hashtable as a hashtable themselves
    foreach($dev in $configMap.GetEnumerator()){
        $rawOIDs = ""
        try{
            $rawOIDs = Get-Content "$dir/$($dev.Value['MIB_File'])" -ErrorAction Stop
        }catch{
            $rawOIDs = 0
        }
        $type01 = $rawOIDs.GetType()
        $type11 = $type01.BaseType.Name
        if($type11 -eq 'Array'){
            # This will contain all the OIDs for a device in its respective hashtable
            $dev.Value['OIDS'] = @{}
            for($i=0;$i -lt $rawOIDs.Count;$i++){
                $tmpArr = $rawOIDs[$i].Split("=")
                $tmpKey = $tmpArr[0].Trim()
                $tmpVal = $tmpArr[1].Trim()
                $dev.Value['OIDS']["$tmpKey"] = $tmpVal
            }
        }
    }
    Return $configMap
}

Function Invoke-SNMP_Req {
    param(
        [String]$Ip,
        [String]$Com,
        [String]$Id
    )
    $SNMP = New-Object -ComObject olePrn.OleSNMP
    $SNMP.open($Ip,$Com,5,1000)
    $Res = $SNMP.get($Id)
    $SNMP.Close()
    Return $Res
}

<#.DESCRIPTION
This function expects the root interface OID to find the total number of interfaces.
The function will loop through the index until it does not recieve an index for an interface.
It will return the total number of interfaces for the 'Get-InterfaceStatus' to query.
#>
Function Search-OID{
    param(
        [String]$Ip,
        [String]$Com,
        [String]$Id
    )

    $totalInt = 0
    $i=1
    while($i -lt 2001){
        $intID = "$Id.$i"
        $intRes = Invoke-SNMP_Req -Ip $Ip -Com $Com -Id $intID
        if($intRes){
            $totalInt = $intRes
            $i++
        }else{
            Break
        }
    }
    Return $totalInt
}

<#.DESCRIPTION
It will then  retrieve the status, speed, and MAC address of each interface.
#>
Function Get-InterfaceStatus {
    param(
        [String]$Ip,
        [String]$Com,
        [String]$DescId,
        [String]$AddrId,
        [String]$StatusId,
        [String]$SpeedId,
        [String]$ErrorId,
        [Int32]$MaxInters
    )
    # Will be composed of hashmaps and returned
    $InterArr = @()

    for($i=1;$i -le $MaxInters;$i++){
        $DescOID = "$DescId.$i"
        $DescRes = Invoke-SNMP_Req -Ip $Ip -Com $Com -Id $DescOID
        $AddrOID = "$AddrId.$i"
        $AddrRes = Invoke-SNMP_Req -Ip $Ip -Com $Com -Id $AddrOID
        $StatOID = "$StatusId.$i"
        $StatRes = Invoke-SNMP_Req -Ip $Ip -Com $Com -Id $StatOID
        $SpeedOID = "$SpeedId.$i"
        $SpeedRes = Invoke-SNMP_Req -Ip $Ip -Com $Com -Id $SpeedOID
        $ErrorOID = "$ErrorId.$i"
        $ErrorRes = Invoke-SNMP_Req -Ip $Ip -Com $Com -Id $ErrorOID

        #Write-Output $AddrRes
        $Stat = ""
        if($StatRes -eq 1){
            $Stat = 'Up'
        }else{
            $Stat = 'Down'
        }
        $Mbps = $SpeedRes / 1000000

        $tempMap = @{
            Interface = $DescRes;
            Address = $AddrRes;
            Status = $Stat
            LinkSpeed = "$Mbps Mbps"
            TotalErrors = $ErrorRes
        }
        $InterArr += $tempMap
    }

    Return $InterArr
}

<#.DESCRIPTION
'Get-DeviceInfo' will request system name, description, uptime, and total number of ICMP messages from the target device.
It will then parse this information and return it as a hashmap.
#>
Function Get-DeviceInfo {
    param(
        [String]$Ip,
        [String]$Com,
        [String]$SysNId,
        [String]$SysDId,
        [String]$TimeId,
        [String]$IcmpId
    )

    $SysOIDS = @{
        Name = $SysNId;
        Description = $SysDId;
        Up_Time = $TimeId;
        ICMP_Messages = $IcmpId
    }

    $SysInfo = @{}
    foreach($OID in $SysOIDS.GetEnumerator()){
        $tempReq = Invoke-SNMP_Req -Ip $Ip -Com $Com -Id $OID.Value
        # Need to convert uptime from hundredths of a second to hours
        if($OID.Key -eq 'Up_Time'){
            $hundSec = $tempReq / 100
            $mins = $hundSec / 60
            [int32]$hours = $mins / 60
            $SysInfo[$OID.Key] = "$hours Hrs"
        }else{
            $SysInfo[$OID.Key] = $tempReq
        }
    }
    Return $SysInfo
}

<#
$DevInfo = Get-DeviceInfo -Ip $IP -Com $ComStr -SysNId $OIDS['SysName'] -SysDId $OIDS['SysDesc'] -TimeId $OIDS['UpTime'] -IcmpId $OIDS['IcmpInMsgs']
Write-Output $DevInfo
Write-Output "--------------------------"

$totInt = Search-OID -Ip $IP -Com $ComStr -Id $OIDS['InterIndex']
$InterStats = Get-InterfaceStatus -Ip $IP -Com $ComStr -DescId $OIDS['InterDesc'] -AddrId $OIDS['InterPhyAddr'] `
    -StatusId $OIDS['InterStatus'] -SpeedId $OIDS['InterSpeed'] -ErrorId $OIDS['InterInErrors'] `
    -MaxInters $totInt

foreach($int in $InterStats.GetEnumerator()){
    Write-Output $int
    Write-Output "--------------------------"
}
#>
$test = Initialize-Devices