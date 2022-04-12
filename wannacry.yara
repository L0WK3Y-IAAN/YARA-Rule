rule wannacry_ruleset {
    meta:
    last_updated = "04-09-2022"
    author = "IAANSEC"
    description = "Yara rule to detect wannacry ransomware."
    hash256 = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"

    strings:
        $MZ_byte = "MZ"
        $querydomain_killswitch = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea" ascii
        $weird_windows_dir_str = "qeriuwjhrf" ascii
        $reg_name = "WanaCrypt0r" ascii
        $service = "Microsoft Security Center (2.0) Service" ascii
        $payload = "tasksche" ascii
        $exe1 = "taskdl" ascii
        $exe2 = "taskse" ascii
        $import = "Crypt" ascii
        $str = "WNcry@2017" ascii
        $decrypt_exe = "@WanaDecryptor@.exe" ascii
        $wnry = "wnry" ascii
        $decrypt = "decrypt" ascii
        $bitcoin = "bitcoin" ascii
        $btcwallet1 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" fullword ascii
        $btcwallet2 = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" fullword ascii
        $btcwallet3 = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" fullword ascii
        
    condition:
        $MZ_byte at 0 and
        5 of them
        
}