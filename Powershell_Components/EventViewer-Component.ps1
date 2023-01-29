
Function Trace-DefenderLogs {
    Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational"
}