
rule Network_Indicators {
    meta:
        description = "Detects network-related suspicious activity"
        severity = "medium"
    strings:
        $url1 = /https?:\/\/[a-z0-9]{20,50}/
        $ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        $socket = "WSASocket" nocase
        $connect = "WSAConnect" nocase
        $download = "URLDownloadToFile" nocase
    condition:
        uint16(0) == 0x5A4D and
        2 of them
}
