# TP-Link RFC1213 OIDS
$OIDS = @{
    SysDesc = ".1.3.6.1.2.1.1.1.0";
    SysName = ".1.3.6.1.2.1.1.5.0";
    UpTime = ".1.3.6.1.2.1.1.3.0";
    IcmpInMsgs = ".1.3.6.1.2.1.5.1.0";
    IcmpInErrors = ".1.3.6.1.2.1.5.2.0";
    IcmpInDestUnreachs = ".1.3.6.1.2.1.5.3.0";
    TcpInErrors =".1.3.6.1.2.1.6.14.0";
    UdpInErrors = ".1.3.6.1.2.1.7.3.0";
    # Interface specific OIDS
    InterIndex = '.1.3.6.1.2.1.2.2.1.1';
    InterDesc = ".1.3.6.1.2.1.2.2.1.2";
    InterSpeed = ".1.3.6.1.2.1.2.2.1.5";
    InterPhyAddr = ".1.3.6.1.2.1.2.2.1.6";
    InterStatus = '.1.3.6.1.2.1.2.2.1.8';
    InterInErrors = ".1.3.6.1.2.1.2.2.1.14"
}

$ComStr = ""
$IP = ''

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

    for($i=1;$i -lt 201;$i++){
        $intID = "$Id.$i"
        $intRes = Invoke-SNMP_Req -Ip $Ip -Com $Com -Id $intID
        if($intRes){
            $totalInt = $intRes
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