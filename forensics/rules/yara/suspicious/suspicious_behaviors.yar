rule Suspicious_Behavior {
    meta:
        description = "Detects suspicious program behaviors"
        author = "Security Tool"
        severity = "medium"
        date = "2024-03-17"

    strings:
        $network1 = "socket(" nocase
        $network2 = "connect(" nocase
        
        $file_ops1 = "CreateFile"
        $file_ops2 = "WriteFile"
        $file_ops3 = "DeleteFile"
        
        $registry1 = "RegCreateKey"
        $registry2 = "RegSetValue"
        
        $process1 = "CreateProcess"
        $process2 = "OpenProcess"
        
        $injection1 = "VirtualAlloc"
        $injection2 = "WriteProcessMemory"

    condition:
        (2 of ($network*)) or
        (2 of ($file_ops*)) or
        (any of ($registry*)) or
        (any of ($process*) and any of ($injection*))
} 