
rule Persistence_Mechanisms {
    meta:
        description = "Detects common persistence mechanisms"
        severity = "high"
    strings:
        $run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $startup = "\\Start Menu\\Programs\\Startup"
        $tasksched = "schtasks" nocase
        $wmi = "\\\\.\root\subscription"
    condition:
        uint16(0) == 0x5A4D and
        any of them
}
