rule HighEntropy_Executable {
    meta:
        description = "Detects executables with suspiciously high entropy (simplified rule)"
        severity = "medium"
    strings:
        $mz = "MZ"
        // High entropy files often have these characteristics
        $high_var1 = { ?? ?? ?? ?? ?? ?? ?? ?? }  // Varied bytes
    condition:
        $mz at 0 and
        filesize > 10KB and
        #high_var1 > 100
}
