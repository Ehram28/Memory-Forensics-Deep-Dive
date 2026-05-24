rule Meterpreter_Patterns
{
    meta:
        description = "Detects Meterpreter/Multi-stage payload style artifacts"
        author = "Memory Forensics Deep Dive"
    strings:
        $m1 = "meterpreter" ascii wide nocase
        $m2 = "meterp" ascii wide nocase
        $m3 = "Invoke-ReflectivePEInjection" ascii wide nocase
        $m4 = "Reflective" ascii wide nocase
        $m5 = "Stager" ascii wide nocase
        $m6 = "VirtualAlloc" ascii wide nocase
        $m7 = "CreateRemoteThread" ascii wide nocase
    condition:
        2 of them
}

