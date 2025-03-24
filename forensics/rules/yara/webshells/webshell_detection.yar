rule PHP_Webshell {
    meta:
        description = "Detects PHP webshells"
        author = "Security Tool"
        severity = "high"
        date = "2024-03-17"

    strings:
        $php_tag = "<?php"
        
        $shell_cmd1 = "shell_exec" nocase
        $shell_cmd2 = "system(" nocase
        $shell_cmd3 = "passthru" nocase
        $shell_cmd4 = "exec(" nocase
        
        $sus_input1 = "$_GET" nocase
        $sus_input2 = "$_POST" nocase
        $sus_input3 = "$_REQUEST" nocase
        
        $eval = "eval(" nocase
        $base64 = "base64_decode(" nocase

    condition:
        $php_tag and
        (
            (any of ($shell_cmd*)) or
            (any of ($sus_input*) and ($eval or $base64))
        )
} 