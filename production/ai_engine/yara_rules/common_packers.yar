
rule Common_Packers {
    meta:
        description = "Detects common packers and protectors"
        severity = "low"
    strings:
        $upx = "UPX0"
        $upx1 = "UPX1"
        $aspack = "ASPack"
        $petite = "Petite"
        $themida = "Themida"
        $vmprotect = "VMProtect"
    condition:
        uint16(0) == 0x5A4D and
        any of them
}
