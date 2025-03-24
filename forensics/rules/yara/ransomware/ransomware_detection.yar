rule Ransomware_Behavior {
    meta:
        description = "Detects common ransomware behaviors"
        author = "Security Tool"
        severity = "critical"
        date = "2024-03-17"

    strings:
        $ransom_note1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase wide ascii
        $ransom_note2 = "DECRYPT YOUR FILES" nocase wide ascii
        $ransom_note3 = "BITCOIN" nocase wide ascii
        
        $extension1 = ".encrypted"
        $extension2 = ".locked"
        $extension3 = ".crypted"
        
        $crypto_api1 = "CryptoAPI"
        $crypto_api2 = "BCryptEncrypt"
        $crypto_api3 = "CryptEncrypt"

    condition:
        (any of ($ransom_note*)) and
        (any of ($extension*)) and
        (any of ($crypto_api*))
} 