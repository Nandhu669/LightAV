rule EICAR_Test_File {
    meta:
        description = "Standard EICAR Anti-Virus Test File"
        author = "Standard"
        severity = "high"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
