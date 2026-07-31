rule EDR_Core_Ransomware_Crypto {
    meta:
        description = "Detects common Ransomware file extensions and encryption strings"
        severity = "CRITICAL"
    strings:
        $s1 = "vssadmin.exe Delete Shadows /All /Quiet" ascii wide nocase
        $s2 = "wbadmin DELETE SYSTEMSTATEBACKUP" ascii wide nocase
        $s3 = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
        $ext1 = ".WannaCry" ascii wide nocase
        $ext2 = ".locky" ascii wide nocase
        $ext3 = ".ryuk" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 1 of them
}

rule EDR_Core_CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike C2 Beacons inside downloaded files"
        severity = "CRITICAL"
    strings:
        $s1 = "%s as %s\\%s: %d" ascii wide
        $s2 = "beacon.x64.dll" ascii wide
        $s3 = "beacon.dll" ascii wide
        $s4 = "IEX (New-Object Net.WebClient).DownloadString" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 1 of them
}

rule EDR_Demo_Hacker_Payload {
    meta:
        description = "Harmless demo rule to safely trigger YARA quarantine on text files"
        severity = "CRITICAL"
    strings:
        $test_string = "HACKER_PAYLOAD_TEST" ascii wide nocase
    condition:
        $test_string
}