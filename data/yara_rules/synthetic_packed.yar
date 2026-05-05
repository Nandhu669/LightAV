rule Synthetic_Simulated_Packed {
    meta:
        description = "Detects the synthetic packed malware test file"
        severity = "high"
    strings:
        $magic = "LIGHTAV_SIMULATED_MALWARE_PAYLOAD_START"
    condition:
        $magic
}
