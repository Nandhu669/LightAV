
rule Suspicious_Strings {
    meta:
        description = "Detects suspicious strings in executables"
        severity = "medium"
    strings:
        $s1 = "cmd.exe /c" nocase
        $s2 = "powershell.exe" nocase
        $s3 = "reg add" nocase
        $s4 = "net user" nocase
        $s5 = "CreateObject" nocase
        $s6 = "WScript.Shell" nocase
        $s7 = "eval(" nocase
        $s8 = "base64" nocase
    condition:
        uint16(0) == 0x5A4D and
        3 of them
}
