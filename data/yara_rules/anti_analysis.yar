
rule Anti_Analysis {
    meta:
        description = "Detects anti-analysis techniques"
        severity = "high"
    strings:
        $dbg1 = "IsDebuggerPresent"
        $dbg2 = "CheckRemoteDebuggerPresent"
        $dbg3 = "NtGlobalFlag"
        $vm1 = "vmware"
        $vm2 = "virtualbox"
        $vm3 = "xen"
        $proc1 = "wireshark.exe" nocase
        $proc2 = "ollydbg.exe" nocase
        $proc3 = "processhacker.exe" nocase
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($dbg*) or any of ($vm*) or 2 of ($proc*))
}
