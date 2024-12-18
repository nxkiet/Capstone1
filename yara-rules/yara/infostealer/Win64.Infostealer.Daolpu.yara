rule Win64_Infostealer_Daolpu : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "DAOLPU"
        description         = "Yara rule that detects Daolpu infostealer."

        tc_detection_type   = "Infostealer"
        tc_detection_name   = "Daolpu"
        tc_detection_factor = 5

    strings:

        $network_communication = {
            48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 7C 24 ?? 41 56 48 83 EC ?? 48 8B D9 49 8B E8 B9
            ?? ?? ?? ?? 4C 8B F2 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B F8 48 85 C0 0F 84 ?? ?? ??
            ?? 4C 8D 05 ?? ?? ?? ?? 48 89 74 24 ?? BA ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 83
            7B ?? ?? 4C 8D 43 ?? 76 ?? 4D 8B 00 BA ?? ?? ?? ?? 48 8B CF E8 ?? ?? ?? ?? BA ?? ??
            ?? ?? 48 8B CF 44 8D 42 ?? E8 ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 8B
            CF E8 ?? ?? ?? ?? 45 33 C0 BA ?? ?? ?? ?? 48 8B CF E8 ?? ?? ?? ?? 48 8B CF E8 ?? ??
            ?? ?? 48 8B C8 48 8B F0 E8 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B C8 48 8B D8 E8 ??
            ?? ?? ?? 49 83 7E ?? ?? 49 8D 56 ?? 76 ?? 48 8B 12 48 8B CB E8 ?? ?? ?? ?? 48 8B CE
            E8 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B C8 48 8B D8 E8 ?? ?? ?? ?? 48 83 7D ?? ??
            48 8D 55 ?? 76 ?? 48 8B 12 49 C7 C0 ?? ?? ?? ?? 48 8B CB E8 ?? ?? ?? ?? 48 8B CE E8
            ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B C8 48 8B D8 E8 ?? ?? ?? ?? 49 C7 C0 ?? ?? ??
            ?? 48 8D 15 ?? ?? ?? ?? 48 8B CB E8 ?? ?? ?? ?? 4C 8B C6 BA ?? ?? ?? ?? 48 8B CF E8
            ?? ?? ?? ?? 48 8B CF E8 ?? ?? ?? ?? 8B E8 85 C0 75 ?? 48 8D 1D ?? ?? ?? ?? 48 8D 05
            ?? ?? ?? ?? EB ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CD 48
            8B D8 E8 ?? ?? ?? ?? 48 8B D0 48 8B CB E8 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8B
            CE E8 ?? ?? ?? ?? 48 8B 74 24 ?? 48 8B CF E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 5C 24
            ?? 33 C0 48 8B 6C 24 ?? 48 8B 7C 24 ?? 48 83 C4 ?? 41 5E C3
        }

        $find_sensitive_files_p1 = {
            48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ?? ?? ?? ?? 48 81 EC ??
            ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? 4C 8B F2 48 8B F9 45 33
            E4 4C 89 65 ?? 0F 57 C0 0F 11 45 ?? 0F 57 C9 F3 0F 7F 4D ?? 49 C7 C0 ?? ?? ?? ?? 49
            FF C0 66 46 39 24 41 75 ?? 48 8B D7 48 8D 4D ?? E8 ?? ?? ?? ?? 90 41 B8 ?? ?? ?? ??
            48 8D 15 ?? ?? ?? ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 48 8D 4D ?? 48 83 7D ?? ?? 48 0F 47
            4D ?? 48 8D 55 ?? FF 15 ?? ?? ?? ?? 4C 8B F8 0F 57 C0 F3 0F 7F 45 ?? 0F 57 C9 F3 0F
            7F 4D ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 89 60 ?? 48 89 45 ?? 48 8D 4D ?? 48 89 08
            49 83 FF ?? 0F 84 ?? ?? ?? ?? 4C 8D 2D ?? ?? ?? ?? F6 45 ?? ?? 0F 84 ?? ?? ?? ?? 0F
            B7 4D ?? 0F B7 45 ?? 66 83 F9 ?? 75 ?? 66 85 C0 0F 84 ?? ?? ?? ?? 66 3B C9 75 ?? 66
            3B C1 75 ?? 66 83 7D ?? ?? 0F 84 ?? ?? ?? ?? 4C 89 64 24 ?? 0F 57 C0 0F 11 44 24 ??
            4C 89 65 ?? 4C 89 65 ?? 49 C7 C0 ?? ?? ?? ?? 66 0F 1F 84 00 ?? ?? 00 00 49 FF C0 66
            42 83 3C 47 ?? 75 ?? 48 8B D7 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 90 41 B8 ?? ?? ?? ?? 48
            8D 15 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 8D 45 ?? 49 C7 C0 ?? ?? ?? ?? 0F
            1F 44 00 ?? 49 FF C0 66 42 83 3C 40 ?? 75 ?? 48 8D 55 ?? 48 8D 4C 24 ?? E8 ?? ?? ??
            ?? 48 8D 4C 24 ?? 48 83 7D ?? ?? 48 0F 47 4C 24 ?? 49 8B D6 E8 ?? ?? ?? ?? 90 48 8D
            4C 24 ?? E8 ?? ?? ?? ?? 4C 8B 45 ?? 49 83 F8 ?? 76 ?? 48 8B 54 24 ?? 48 8D 4C 24 ??
            E8 ?? ?? ?? ?? 4C 89 65 ?? 48 C7 45 ?? ?? ?? ?? ?? 66 44 89 64 24 ?? 48 8B 4C 24 ??
            4C 89 64 24 ?? E9 ?? ?? ?? ?? 4C 89 65 ?? 0F 57 C0 0F 11 45 ?? 4C 89 65 ?? 4C 89 65
            ?? 48 8D 45 ?? 49 C7 C0 ?? ?? ?? ?? 49 FF C0 66 42 83 3C 40 ?? 75 ?? 48 8D 55 ?? 48
        }

        $find_sensitive_files_p2 = {
            8D 4D ?? E8 ?? ?? ?? ?? 90 4C 8D 55 ?? 48 8B 5D ?? 48 8B 75 ?? 48 83 FE ?? 4C 0F 47
            D3 4C 8B 5D ?? 49 83 FB ?? 72 ?? 49 8D 4B ?? 48 C7 C0 ?? ?? ?? ?? 48 3B C8 48 0F 42
            C1 4D 8D 0C 42 4D 8B C1 4D 2B C5 66 41 83 39 ?? 75 ?? BA ?? ?? ?? ?? 49 8B C5 42 0F
            B7 0C 00 66 3B 08 75 ?? 48 83 C0 ?? 48 83 EA ?? 75 ?? 4D 2B CA 49 D1 F9 EB ?? 4D 3B
            CA 74 ?? 49 83 E9 ?? 49 83 E8 ?? EB ?? 49 C7 C1 ?? ?? ?? ?? 49 83 F9 ?? 0F 84 ?? ??
            ?? ?? 49 FF C1 4C 89 64 24 ?? 0F 57 C0 0F 11 44 24 ?? 4C 89 65 ?? 4C 89 65 ?? 4D 3B
            D9 0F 82 ?? ?? ?? ?? 4D 2B D9 49 C7 C0 ?? ?? ?? ?? 4D 3B D8 4D 0F 42 C3 48 8D 45 ??
            48 83 FE ?? 48 0F 47 C3 4A 8D 14 48 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 90 48 8D 4C 24 ??
            48 83 7D ?? ?? 48 0F 47 4C 24 ?? 48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 84 ??
            ?? ?? ?? 48 8D 4C 24 ?? 48 83 7D ?? ?? 48 0F 47 4C 24 ?? 48 8D 15 ?? ?? ?? ?? E8 ??
            ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8D 4C 24 ?? 48 83 7D ?? ?? 48 0F 47 4C 24 ?? 48
            8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8D 4C 24 ?? 48 83 7D ??
            ?? 48 0F 47 4C 24 ?? 48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48
            8D 4C 24 ?? 48 83 7D ?? ?? 48 0F 47 4C 24 ?? 48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85
            C0 74 ?? 48 8D 4C 24 ?? 48 83 7D ?? ?? 48 0F 47 4C 24 ?? 48 8D 15 ?? ?? ?? ?? E8 ??
            ?? ?? ?? 85 C0 74 ?? 48 8D 4C 24 ?? 48 83 7D ?? ?? 48 0F 47 4C 24 ?? 48 8D 15 ?? ??
            ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8D 4C 24 ?? 48 83 7D ?? ?? 48 0F 47 4C 24 ?? 48
            8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 4C 89 64 24 ?? 0F 57 C0 0F
            11 44 24 ?? 4C 89 64 24 ?? 4C 89 64 24 ?? 49 C7 C0 ?? ?? ?? ?? 49 FF C0 66 42 83 3C
        }

        $find_sensitive_files_p3 = {
            47 ?? 75 ?? 48 8B D7 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 90 41 B8 ?? ?? ?? ?? 48 8D 15 ??
            ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 8B D0 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 90 48
            8D 55 ?? 48 83 7D ?? ?? 48 0F 47 55 ?? 4C 8B 45 ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48
            8B D0 48 8D 4D ?? E8 ?? ?? ?? ?? 90 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 4C 8B 44 24 ?? 49
            83 F8 ?? 76 ?? 48 8B 54 24 ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 4C 89 64 24 ?? 48 C7 44
            24 ?? ?? ?? ?? ?? 66 44 89 64 24 ?? 48 8B 4C 24 ?? 4C 89 64 24 ?? BA ?? ?? ?? ?? E8
            ?? ?? ?? ?? 90 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 4C 8B 44 24 ?? 49 83 F8 ?? 76 ?? 48 8B
            54 24 ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 4C 89 64 24 ?? 48 C7 44 24 ?? ?? ?? ?? ?? 66
            44 89 64 24 ?? 48 8B 4C 24 ?? 4C 89 64 24 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 49 8B 46
            ?? 49 3B 46 ?? 74 ?? 48 8D 55 ?? 48 8B C8 E8 ?? ?? ?? ?? 49 8B 5E ?? BA ?? ?? ?? ??
            48 8D 4D ?? E8 ?? ?? ?? ?? 49 8B 0E 48 83 C1 ?? 48 8B 01 48 85 C0 74 ?? 48 39 58 ??
            72 ?? 77 ?? 4C 89 20 48 8B 40 ?? 48 89 01 EB ?? 48 8D 48 ?? 48 8B 01 48 85 C0 75 ??
            48 8D 4D ?? E8 ?? ?? ?? ?? 49 83 46 ?? ?? EB ?? 4C 8D 45 ?? 48 8B D0 49 8B CE E8 ??
            ?? ?? ?? 90 48 8D 4D ?? E8 ?? ?? ?? ?? 4C 8B 45 ?? 49 83 F8 ?? 76 ?? 48 8B 55 ?? 48
            8D 4D ?? E8 ?? ?? ?? ?? 4C 89 65 ?? 48 C7 45 ?? ?? ?? ?? ?? 66 44 89 65 ?? 48 8B 4D
            ?? 4C 89 65 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 4C 8B
            45 ?? 49 83 F8 ?? 76 ?? 48 8B 54 24 ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 4C 89 65 ?? 48
            C7 45 ?? ?? ?? ?? ?? 66 44 89 64 24 ?? 48 8B 4C 24 ?? 4C 89 64 24 ?? BA ?? ?? ?? ??
            E8 ?? ?? ?? ?? 90 48 8D 4D ?? E8 ?? ?? ?? ?? 4C 8B 45 ?? 49 83 F8 ?? 76 ?? 48 8B 55
            ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 4C 89 65 ?? 48 C7 45 ?? ?? ?? ?? ?? 66 44 89 65 ?? 48
        }

        $parse_firefox_configuration_p1 = {
            48 89 5C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 55 41 54 41 55 41 56 41 57 48 8D AC 24
            ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ??
            48 8B F1 48 89 4C 24 ?? 45 33 ED 44 89 6C 24 ?? 0F 57 C0 0F 11 01 0F 11 41 ?? 4C 89
            29 4C 89 69 ?? 4C 89 69 ?? 4C 89 69 ?? 41 8D 4D ?? E8 ?? ?? ?? ?? 4C 89 68 ?? 48 89
            06 48 89 30 C7 44 24 ?? ?? ?? ?? ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 90 48 8D 4D ?? E8 ??
            ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? 4C 8B 75 ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 49 2B C6
            48 83 F8 ?? 0F 82 ?? ?? ?? ?? 4C 8D 65 ?? 48 83 7D ?? ?? 4C 0F 47 65 ?? 4C 89 6C 24
            ?? 0F 57 C0 0F 11 44 24 ?? 0F 57 C9 F3 0F 7F 4C 24 ?? 4D 8D 7E ?? 41 8D 5D ?? 48 8D
            7C 24 ?? 48 8D 44 24 ?? 48 89 85 ?? ?? ?? ?? 8D 4B ?? E8 ?? ?? ?? ?? 48 89 85 ?? ??
            ?? ?? 48 8D 4C 24 ?? 48 89 08 4C 89 68 ?? 48 89 44 24 ?? 8D 4B ?? 4C 3B FB 76 ?? 49
            8B DF 48 83 CB ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 3B D8 76 ?? 48 8B D8 EB ?? 48 3B
            D9 48 0F 42 D9 48 8D 4B ?? E8 ?? ?? ?? ?? 48 8B F8 48 89 44 24 ?? 4C 89 7C 24 ?? 48
            89 5C 24 ?? 4D 8B C6 49 8B D4 48 8B CF E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 66 42 89 04
            37 0F B6 05 ?? ?? ?? ?? 42 88 44 37 ?? 42 C6 04 3F ?? C7 44 24 ?? ?? ?? ?? ?? 48 8D
            54 24 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 90 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 4C 8B 44 24 ??
            49 83 F8 ?? 76 ?? 49 FF C0 48 8B 54 24 ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 66 0F 6F 05
            ?? ?? 12 00 F3 0F 7F 44 24 ?? C6 44 24 ?? ?? 48 8B 4C 24 ?? 4C 89 6C 24 ?? BA ?? ??
            ?? ?? E8 ?? ?? ?? ?? 48 8D 55 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 90 0F 57 C0 0F 11 45 ??
            0F 11 45 ?? 48 8D 55 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 90 48 8D 4D ?? E8 ?? ?? ?? ?? 90
        }

        $parse_firefox_configuration_p2 = {
            4C 89 6C 24 ?? 0F 57 C0 0F 11 44 24 ?? 4C 89 6C 24 ?? 4C 89 6C 24 ?? 48 8B 7D ?? 4C
            8D 75 ?? 48 83 7D ?? ?? 4C 0F 47 75 ?? 49 BC ?? ?? ?? ?? ?? ?? ?? ?? 49 3B FC 0F 87
            ?? ?? ?? ?? 48 8D 44 24 ?? 48 89 85 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89
            85 ?? ?? ?? ?? 48 8D 4C 24 ?? 48 89 08 4C 89 68 ?? 48 89 44 24 ?? 48 83 FF ?? 77 ??
            48 89 7C 24 ?? BA ?? ?? ?? ?? 48 89 54 24 ?? 41 0F 10 06 0F 11 44 24 ?? EB ?? 48 8B
            DF 48 83 CB ?? 49 3B DC 76 ?? 49 8B DC EB ?? 48 83 FB ?? B8 ?? ?? ?? ?? 48 0F 42 D8
            48 8D 4B ?? E8 ?? ?? ?? ?? 48 89 44 24 ?? 48 89 7C 24 ?? 48 89 5C 24 ?? 4C 8D 47 ??
            49 8B D6 48 8B C8 E8 ?? ?? ?? ?? 90 48 8B 54 24 ?? F2 0F 10 05 ?? ?? ?? ?? F2 0F 11
            85 ?? ?? ?? ?? 0F B6 05 ?? ?? ?? ?? 88 85 ?? ?? ?? ?? 48 8D 4C 24 ?? 48 83 FA ?? 48
            0F 47 4C 24 ?? FF 15 ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B D8 48
            85 C0 75 ?? FF 15 ?? ?? ?? ?? 8B D0 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 4C 24
            ?? E8 ?? ?? ?? ?? 4C 8B 44 24 ?? 49 83 F8 ?? 76 ?? 49 FF C0 48 8B 54 24 ?? 48 8D 4C
            24 ?? E8 ?? ?? ?? ?? 4C 89 6C 24 ?? 48 C7 44 24 ?? ?? ?? ?? ?? C6 44 24 ?? ?? 48 8B
            4C 24 ?? 4C 89 6C 24 ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 DB 75 ?? 48 8D 15 ?? ??
            ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ??
            ?? ?? 48 89 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? 48 89 05
            ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48
            8D 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ??
            ?? 48 8B CB FF 15 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B CB FF
            15 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B CB FF 15
        }

        $parse_firefox_configuration_p3 = {
            4C 8B 7D ?? 49 8B C4 49 2B C7 48 83 F8 ?? 0F 82 ?? ?? ?? ?? 4C 8D 65 ?? 48 83 7D ??
            ?? 4C 0F 47 65 ?? 4C 89 6C 24 ?? 0F 57 C0 0F 11 44 24 ?? 0F 57 C9 F3 0F 7F 4D ?? 4D
            8D 77 ?? BB ?? ?? ?? ?? 48 8D 7C 24 ?? 48 8D 44 24 ?? 48 89 85 ?? ?? ?? ?? 8D 4B ??
            E8 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 8D 4C 24 ?? 48 89 08 4C 89 68 ?? 48 89 44 24
            ?? 4C 3B F3 76 ?? 49 8B DE 48 83 CB ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 3B D8 76 ??
            48 8B D8 EB ?? 48 83 FB ?? B8 ?? ?? ?? ?? 48 0F 42 D8 48 8D 4B ?? E8 ?? ?? ?? ?? 48
            8B F8 48 89 44 24 ?? 4C 89 75 ?? 48 89 5D ?? 4D 8B C7 49 8B D4 48 8B CF E8 ?? ?? ??
            ?? 42 C7 04 3F ?? ?? ?? ?? 42 C6 04 37 ?? C7 44 24 ?? ?? ?? ?? ?? 48 8B 05 ?? ?? ??
            ?? 48 8D 4C 24 ?? 48 83 7D ?? ?? 48 0F 47 4C 24 ?? FF D0 4C 8B 75 ?? 48 8B 5D ?? 49
            3B DE 0F 84 ?? ?? ?? ?? 48 83 C3 ?? 0F 1F 40 ?? 48 8D 43 ?? 48 8D 4D ?? 48 3B C8 74
            ?? 48 8B D3 48 83 7B ?? ?? 76 ?? 48 8B 13 4C 8B 43 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 48
            8D 53 ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ??
            ?? 49 C7 C0 ?? ?? ?? ?? 0F 1F 40 ?? 49 FF C0 42 80 3C 00 ?? 75 ?? 48 8B D0 48 8D 4D
            ?? E8 ?? ?? ?? ?? 48 8D 53 ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ??
            48 8B C8 E8 ?? ?? ?? ?? 49 C7 C0 ?? ?? ?? ?? 0F 1F 44 00 ?? 49 FF C0 42 80 3C 00 ??
            75 ?? 48 8B D0 48 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 7E ?? 48 3B 7E ?? 74 ?? 48
            89 BD ?? ?? ?? ?? 48 8D 55 ?? 48 8B CF E8 ?? ?? ?? ?? 90 48 8D 4F ?? 48 8D 55 ?? E8
            ?? ?? ?? ?? 90 48 8D 4F ?? 48 8D 95 ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 48 8B 56 ?? 4C 8B
            C2 48 8B CE E8 ?? ?? ?? ?? 48 83 46 ?? ?? EB ?? 4C 8D 45 ?? 48 8B D7 48 8B CE E8 ??
            ?? ?? ?? 48 83 C3 ?? 48 8D 43 ?? 49 3B C6 0F 85 ?? ?? ?? ?? 48 8D 4C 24
        }

        $collect_browser_passwords_p1 = {
            48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ?? ?? ?? ?? 48 81 EC ??
            ?? ?? ?? 0F 29 B4 24 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ??
            48 63 DA 48 8B F9 48 89 4D ?? C7 44 24 ?? ?? ?? ?? ?? 0F 57 C0 0F 11 01 0F 11 41 ??
            45 33 ED 4C 89 29 4C 89 69 ?? 4C 89 69 ?? 4C 89 69 ?? 41 8D 4D ?? E8 ?? ?? ?? ?? 4C
            89 68 ?? 48 89 07 48 89 38 C7 44 24 ?? ?? ?? ?? ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 90 48
            8D 0C 9B 4C 8D 05 ?? ?? ?? ?? 49 8D 50 ?? 48 8D 14 CA 49 83 7C C8 ?? ?? 76 ?? 48 8B
            12 4D 8B 44 C8 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8B D0 48 8D 4D ?? E8 ?? ?? ?? ?? C7 44
            24 ?? ?? ?? ?? ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 4C 8B 45 ?? 49 83 F8 ?? 76 ?? 49 FF C0
            48 8B 55 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 66 0F 6F 05 ?? ?? 12 00 F3 0F 7F 45 ?? C6 45
            ?? ?? 48 8B 4D ?? 4C 89 6D ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 48 8D 4D ?? E8 ?? ??
            ?? ?? 84 C0 0F 84 ?? ?? ?? ?? 48 8D 55 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 90 8B CB E8 ??
            ?? ?? ?? 4C 8B E0 4C 89 6D ?? 4C 89 6D ?? 0F 57 C0 0F 11 45 ?? 0F 57 C9 F3 0F 7F 4D
            ?? 41 B8 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 90 4C 89 6D ??
            48 8D 4D ?? 48 83 7D ?? ?? 48 0F 47 4D ?? 48 8D 55 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ??
            48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8 48 8B 4D ?? FF 15
            ?? ?? ?? ?? 48 8B D0 48 8B CB E8 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? E9 ?? ?? ?? ??
            48 8D 55 ?? 48 83 7D ?? ?? 48 0F 47 55 ?? 4C 89 6C 24 ?? 4C 8D 4D ?? 41 B8 ?? ?? ??
            ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 48 8D 15 ?? ?? ?? ?? EB ?? 48 8B 4D ??
            FF 15 ?? ?? ?? ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? 66 0F 1F 84 00 ?? ?? 00 00 33 D2 48 8B
            4D ?? FF 15 ?? ?? ?? ?? 4C 8B F8 BA ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 48 8B
        }

        $collect_browser_passwords_p2 = {
            F0 BA ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 4C 8B F0 BA ?? ?? ?? ?? 48 8B 4D ??
            FF 15 ?? ?? ?? ?? 48 8B D8 BA ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? BA ?? ?? ??
            ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 90 48 C7 C0 ?? ?? ?? ??
            48 FF C0 80 3C 03 ?? 75 ?? 48 83 F8 ?? 0F 86 ?? ?? ?? ?? 41 0F 10 34 24 4C 89 6C 24
            ?? 0F 57 C0 0F 11 44 24 ?? 4C 89 6C 24 ?? 4C 89 6C 24 ?? 49 C7 C0 ?? ?? ?? ?? 66 0F
            1F 44 00 ?? 49 FF C0 42 80 3C 03 ?? 75 ?? 48 8B D3 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 0F
            29 74 24 ?? 4C 8D 44 24 ?? 48 8D 54 24 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 90 48 8D 15 ??
            ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B C8 49 8B D7 E8 ?? ?? ?? ?? 48 8B
            C8 E8 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B C8
            48 8B D6 E8 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ??
            ?? ?? E8 ?? ?? ?? ?? 48 8B C8 49 8B D6 E8 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8D
            15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 55 ?? 48 83 7D ?? ?? 48 0F
            47 55 ?? 4C 8B 45 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8B C8 E8 ??
            ?? ?? ?? 49 C7 C0 ?? ?? ?? ?? 49 FF C0 42 80 3C 06 ?? 75 ?? 48 8B D6 48 8D 4D ?? E8
            ?? ?? ?? ?? 49 C7 C0 ?? ?? ?? ?? 49 FF C0 43 80 3C 06 ?? 75 ?? 49 8B D6 48 8D 4D ??
            E8 ?? ?? ?? ?? 48 8D 55 ?? 48 83 7D ?? ?? 48 0F 47 55 ?? 4C 8B 45 ?? 48 8D 8D ?? ??
            ?? ?? E8 ?? ?? ?? ?? 48 8B 5F ?? 48 3B 5F ?? 74 ?? 48 89 5C 24 ?? 48 8D 55 ?? 48 8B
        }

        $collect_browser_passwords_p3 = {
            CB E8 ?? ?? ?? ?? 90 48 8D 4B ?? 48 8D 55 ?? E8 ?? ?? ?? ?? 90 48 8D 4B ?? 48 8D 95
            ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 48 8B 57 ?? 4C 8B C2 48 8B CF E8 ?? ?? ?? ?? 48 83 47
            ?? ?? EB ?? 4C 8D 45 ?? 48 8B D3 48 8B CF E8 ?? ?? ?? ?? 90 48 8D 4D ?? E8 ?? ?? ??
            ?? 4C 8B 45 ?? 49 83 F8 ?? 76 ?? 49 FF C0 48 8B 55 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 4C
            89 6D ?? 48 C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 48 8B 4D ?? 4C 89 6D ?? BA ?? ?? ?? ??
            E8 ?? ?? ?? ?? 90 48 8D 4D ?? E8 ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 83 F8 ??
            0F 84 ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? BA ?? ?? ?? ?? 49 8B CC E8 ?? ?? ??
            ?? 90 48 8D 4D ?? E8 ?? ?? ?? ?? 4C 8B 45 ?? 49 83 F8 ?? 76 ?? 49 FF C0 48 8B 55 ??
            48 8D 4D ?? E8 ?? ?? ?? ?? 66 0F 6F 05 ?? ?? 12 00 48 8B 4D ?? F3 0F 7F 45 ?? C6 45
            ?? ?? 4C 89 6D ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 48 8D 4D ?? E8 ?? ?? ?? ?? 4C 8B
            45 ?? 49 83 F8 ?? 76 ?? 49 FF C0 48 8B 55 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 66 0F 6F 05
            ?? ?? 12 00 48 8B 4D ?? F3 0F 7F 45 ?? C6 45 ?? ?? 4C 89 6D ?? BA ?? ?? ?? ?? E8 ??
            ?? ?? ?? 90 48 8D 4D ?? E8 ?? ?? ?? ?? 4C 8B 45 ?? 49 83 F8 ?? 76 ?? 49 FF C0 48 8B
            55 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 66 0F 6F 05 ?? ?? 12 00 48 8B 4D ?? F3 0F 7F 45 ??
            C6 45 ?? ?? 4C 89 6D ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 48 8B C7 48 8B 8D ?? ?? ??
            ?? 48 33 CC E8 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ?? ?? 0F 28 B4 24 ?? ?? ?? ?? 48 81 C4
            ?? ?? ?? ?? 41 5F 41 5E 41 5D 41 5C 5F 5E 5D C3
        }

        $collect_cookies_p1 = {
            48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ?? ?? ?? ?? 48 81 EC ??
            ?? ?? ?? 0F 29 B4 24 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ??
            48 63 DA 4C 8B F1 48 89 4D ?? C7 44 24 ?? ?? ?? ?? ?? 0F 57 C0 0F 11 01 0F 11 41 ??
            33 FF 48 89 39 48 89 79 ?? 48 89 79 ?? 48 89 79 ?? 8D 4F ?? E8 ?? ?? ?? ?? 48 89 78
            ?? 49 89 06 4C 89 30 C7 44 24 ?? ?? ?? ?? ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 90 48 8D 0C
            9B 4C 8D 05 ?? ?? ?? ?? 49 8D 50 ?? 48 8D 14 CA 49 83 7C C8 ?? ?? 76 ?? 48 8B 12 4D
            8B 44 C8 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8B D0 48 8D 4D ?? E8 ?? ?? ?? ?? C7 44 24 ??
            ?? ?? ?? ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 4C 8B 45 ?? 49 83 F8 ?? 76 ?? 49 FF C0 48 8B
            55 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 66 0F 6F 05 ?? ?? 12 00 F3 0F 7F 45 ?? C6 45 ?? ??
            48 8B 4D ?? 48 89 7D ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 48 8D 4D ?? E8 ?? ?? ?? ??
            84 C0 0F 84 ?? ?? ?? ?? 8B CB E8 ?? ?? ?? ?? 48 89 44 24 ?? 48 89 7D ?? 48 89 7D ??
            0F 57 C0 0F 11 45 ?? 0F 57 C9 F3 0F 7F 4D ?? 41 B8 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ??
            48 8D 4D ?? E8 ?? ?? ?? ?? 90 48 89 7D ?? 48 8D 4D ?? 48 83 7D ?? ?? 48 0F 47 4D ??
            48 8D 55 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ??
            E8 ?? ?? ?? ?? 48 8B D8 48 8B 4D ?? FF 15 ?? ?? ?? ?? 48 8B D0 48 8B CB E8 ?? ?? ??
            ?? 48 8B C8 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8D 55 ?? 48 83 7D ?? ?? 48 0F 47 55 ??
            48 89 7C 24 ?? 4C 8D 4D ?? 41 B8 ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 85 C0 74
            ?? 48 8D 15 ?? ?? ?? ?? EB ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 83 F8 ?? 0F 85 ?? ?? ??
            ?? 0F 1F 80 ?? ?? ?? ?? 33 D2 48 8B 4D ?? FF 15 ?? ?? ?? ?? 48 8B F0 BA ?? ?? ?? ??
            48 8B 4D ?? FF 15 ?? ?? ?? ?? 48 8B F8 BA ?? ?? ?? ?? 48 8B 4D ?? FF 15
        }

        $collect_cookies_p2 = {
            4C 8B F8 BA ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 48 8B D8 BA ?? ?? ?? ?? 48 8B
            4D ?? FF 15 ?? ?? ?? ?? 4C 8B E0 BA ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 44 8B
            E8 48 85 F6 75 ?? 48 85 FF 75 ?? 48 85 DB 0F 84 ?? ?? ?? ?? 48 C7 C1 ?? ?? ?? ?? 48
            FF C1 80 3C 0E ?? 75 ?? 48 85 C9 75 ?? 48 C7 C0 ?? ?? ?? ?? 0F 1F 84 00 ?? ?? ?? ??
            48 FF C0 80 3C 07 ?? 75 ?? 48 85 C0 75 ?? 48 C7 C0 ?? ?? ?? ?? 48 FF C0 80 3C 03 ??
            75 ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 90 45 85 ED 0F 8E ?? ??
            ?? ?? 48 C7 C0 ?? ?? ?? ?? 48 FF C0 80 3C 03 ?? 75 ?? 48 83 F8 ?? 0F 86 ?? ?? ?? ??
            48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B C8 48 8B D6 E8 ?? ??
            ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ??
            ?? 48 8B C8 48 8B D7 E8 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8B 44 24 ?? 0F 10 30
            45 33 ED 4C 89 6C 24 ?? 0F 57 C0 0F 11 44 24 ?? 4C 89 6C 24 ?? 4C 89 6C 24 ?? 49 C7
            C0 ?? ?? ?? ?? 0F 1F 80 ?? ?? ?? ?? 49 FF C0 46 38 2C 03 75 ?? 48 8B D3 48 8D 4C 24
            ?? E8 ?? ?? ?? ?? 0F 29 74 24 ?? 4C 8D 44 24 ?? 48 8D 54 24 ?? 48 8D 4D ?? E8 ?? ??
            ?? ?? 90 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 55 ?? 48 83
            7D ?? ?? 48 0F 47 55 ?? 4C 8B 45 ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ??
            48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B C8 49 8B D7 E8 ?? ??
            ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ??
            ?? 48 8B C8 49 8B D4 E8 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 8B C8 E8
        }

        $collect_cookies_p3 = {
            49 C7 C0 ?? ?? ?? ?? 90 49 FF C0 42 80 3C 06 ?? 75 ?? 48 8B D6 48 8D 4D ?? E8 ?? ??
            ?? ?? 49 C7 C0 ?? ?? ?? ?? 0F 1F 00 49 FF C0 42 80 3C 07 ?? 75 ?? 48 8B D7 48 8D 4D
            ?? E8 ?? ?? ?? ?? 49 C7 C0 ?? ?? ?? ?? 0F 1F 00 49 FF C0 43 80 3C 07 ?? 75 ?? 49 8B
            D7 48 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 49 C7 C0 ?? ?? ?? ?? 49 FF C0 43 80 3C 04 ??
            75 ?? 49 8B D4 48 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 55 ?? 48 83 7D ?? ?? 48 0F
            47 55 ?? 4C 8B 45 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 49 8B 56 ?? 4C 8D 45 ?? 49 3B 56 ??
            74 ?? E8 ?? ?? ?? ?? 49 8B 56 ?? 4C 8B C2 49 8B CE E8 ?? ?? ?? ?? 49 81 46 ?? ?? ??
            ?? ?? EB ?? 49 8B CE E8 ?? ?? ?? ?? 90 48 8D 4D ?? E8 ?? ?? ?? ?? 4C 8B 45 ?? 49 83
            F8 ?? 76 ?? 49 FF C0 48 8B 55 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 4C 89 6D ?? 48 C7 45 ??
            ?? ?? ?? ?? C6 45 ?? ?? 48 8B 4D ?? 4C 89 6D ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 48
            8D 4D ?? E8 ?? ?? ?? ?? 48 8B 4D ?? FF 15 ?? ?? ?? ?? 83 F8 ?? 0F 84 ?? ?? ?? ?? 33
            FF 48 8D 4D ?? E8 ?? ?? ?? ?? 4C 8B 45 ?? 49 83 F8 ?? 76 ?? 49 FF C0 48 8B 55 ?? 48
            8D 4D ?? E8 ?? ?? ?? ?? 66 0F 6F 05 ?? ?? 12 00 48 8B 4D ?? F3 0F 7F 45 ?? C6 45 ??
            ?? 48 89 7D ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 48 8D 4D ?? E8 ?? ?? ?? ?? 4C 8B 45
            ?? 49 83 F8 ?? 76 ?? 49 FF C0 48 8B 55 ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 66 0F 6F 05 ??
            ?? 12 00 48 8B 4D ?? F3 0F 7F 45 ?? C6 45 ?? ?? 48 89 7D ?? BA ?? ?? ?? ?? E8 ?? ??
            ?? ?? 90 49 8B C6 48 8B 8D ?? ?? ?? ?? 48 33 CC E8 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ??
            ?? 0F 28 B4 24 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? 41 5F 41 5E 41 5D 41 5C 5F 5E 5D C3
        }

    condition:
        uint16(0) == 0x5A4D and
        (
            (
                $network_communication
            ) and
            (
                all of ($find_sensitive_files_p*)
            ) and
            (
                all of ($parse_firefox_configuration_p*)
            ) and
            (
                all of ($collect_browser_passwords_p*)
            ) and
            (
                all of ($collect_cookies_p*)
            )
        )
}