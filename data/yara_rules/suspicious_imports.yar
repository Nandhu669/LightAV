
rule Suspicious_API_Imports {
    meta:
        description = "Detects suspicious Windows API imports"
        severity = "medium"
    strings:
        $api1 = "VirtualAllocEx"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
        $api4 = "NtUnmapViewOfSection"
        $api5 = "SetWindowsHookEx"
        $api6 = "GetAsyncKeyState"
    condition:
        uint16(0) == 0x5A4D and
        2 of them
}
