rule Suspicious_PowerShell
{
    meta:
        description = "Detects common malicious PowerShell abuse patterns"
        author = "Memory Forensics Deep Dive"
    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "-enc" ascii wide nocase
        $ps3 = "-EncodedCommand" ascii wide nocase
        $ps4 = "FromBase64String" ascii wide nocase
        $ps5 = "Invoke-Expression" ascii wide nocase
        $ps6 = "IEX" ascii wide nocase
        $ps7 = "DownloadString" ascii wide nocase
        $ps8 = "New-Object" ascii wide nocase
        $ps9 = "Net.WebClient" ascii wide nocase
    condition:
        any of them
}

