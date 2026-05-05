
rule HighEntropy_Executable {
    meta:
        description = "Detects executables with suspiciously high entropy"
        severity = "high"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0 and
        math.entropy(0, filesize) > 7.5
}
