rule Credential_Dumping
{
    meta:
        description = "Detects credential dumping / LSASS related strings"
        author = "Memory Forensics Deep Dive"
    strings:
        $a = "lsass.exe" ascii wide nocase
        $b = "sekurlsa" ascii wide nocase
        $c = "mimikatz" ascii wide nocase
        $d = "procdump" ascii wide nocase
        $e = "comsvcs.dll" ascii wide nocase
        $f = "MiniDump" ascii wide nocase
        $g = "WERFault" ascii wide nocase
        $h = "Dbghelp" ascii wide nocase
    condition:
        any of them
}

