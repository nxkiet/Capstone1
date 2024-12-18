import "pe"

rule ASPack_packer {
    meta: 
        author = ""
        version = "1"
        des = "Detection of ASPack packer"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
                pe.sections[i].name == ".aspack" or 
                pe.sections[i].name == ".adata" or 
                pe.sections[i].name == "ASPack" or 
                pe.sections[i].name == ".ASPack" 
        )
}

rule UPX_packer {
    meta: 
        author = ""
        version = "1"
        des = "Detection of UPX packer"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
                pe.sections[i].name == "UPX0" or 
                pe.sections[i].name == "UPX1" or 
                pe.sections[i].name == "UPX2" or
                pe.sections[i].name == "UPX!" or 
                pe.sections[i].name == ".UPX0" or 
                pe.sections[i].name == ".UPX1" or 
                pe.sections[i].name == ".UPX2" or 
                pe.sections[i].name == ".UPX!"
        )
}

rule VMProtect_packer{
    meta: 
        author = ""
        version = "1"
        des = "Detection of VM Protect packer"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
                pe.sections[i].name == ".vmp0" or 
                pe.sections[i].name == ".vmp1"
        )
}

rule nspack_ProduKey{
    meta: 
        author = ""
        version = "1.93"
        des = "Detection of nspack_ProduKey"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == "nsnp0" or 
            pe.sections[i].name == "nsnp1"
        )
}

rule neolite_BlueScreenView{
    meta: 
        author = ""
        version = "1.55"
        des = "Detection of neolite_BlueScreenView"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == ".neolit"
        )
}

// rule pecompact{
//     meta: 
//         author = ""
//         version = "1.55"
//         des = "Detection of pecompact_"
//     condition:
//         filesize < 1MB and
//         uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
//             pe.sections[i].name == ""
//         )
// //khong tim thay loi name 
// }

rule petite_EFClock{
    meta: 
        author = ""
        version = "2.08"
        des = "Detection of petite_EFClock"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == ".pelite"
        )
}

rule packman_notmyfaultc{
    meta: 
        author = ""
        version = "4.01"
        des = "Detection of packman_notmyfaultc"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == ".PACKMAN"
        )
}

rule rlpack_EventLogChannelsView{
    meta: 
        author = ""
        version = "1.44"
        des = "Detection of rlpack_EventLogChannelsView."
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == "packed" or 
            pe.sections[i].name == "RLPack" 
        )
}

// rule telock_BatteryInfoView{
//     meta: 
//         author = ""
//         version = "1.23"
//         des = "Detection of telock_BatteryInfoView."
//     condition:
//         uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
//             pe.sections[i].name == "" 
//         )
//         //n/a

// }

rule yoda_protector_FullEventLogView{
    meta: 
        author = ""
        version = "1.30"
        des = "Detection of yoda-protector_FullEventLogView."
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == ".yP"
        )
}

rule yoda_crypter_WinLogOnView{
    meta: 
        author = ""
        version = "1.30"
        des = "Detection of yoda-crypter_WinLogOnView."
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == "yC"
        )
}

rule alienyze_7z {
    meta: 
        author = ""
        version = "3.12"
        des = "Detection of alienyze_7z"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
                pe.sections[i].name == ".alien" 
        )
}

// rule bero_ADExplorer{
//     meta: 
//         author = ""
//         version = "1.44"
//         des = "Detection of bero_ADExplorer"
//     condition:
//         uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
//             pe.sections[i].name == "packerBY"or
//             pe.sections[i].name == "bero^fr"or
//         )
// }

rule jdpack_7z{
    meta: 
        author = ""
        version = "3.12"
        des = "Detection of jdpack_7z"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == ".jdpack"
        )
}

rule mpress_accesschk{
    meta: 
        author = ""
        version = "6.12"
        des = "Detection of mpress_accesschk"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == ".MPRESS1"or
            pe.sections[i].name == ".MPRESS2"
        )
}

rule amber_accesschk{
    meta: 
        author = ""
        version = "2.1"
        des = "Detection of amber_accesschk"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == ".qDUUtb8"
        )
}

rule enigmavb_7z{
    meta: 
        author = ""
        version = "3,12,0,0"
        des = "Detection of enigmavb_7z"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == ".enigma1"or
            pe.sections[i].name == ".enigma2"
        )
}

rule eronana_7z{
    meta: 
        author = ""
        version = "3,12,0,0"
        des = "Detection of eronana_7z"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == ".packer"
        )
}

rule exe32pack_AddInProcess{
    meta: 
        author = ""
        version = "3.5.30729.5420 built by: Win7SP1"
        des = "Detection of exe32pack_AddInProcess"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == ".i"
        )
}

rule expressor_accesschk{
    meta: 
        author = ""
        version = "6.12"
        des = "Detection of expressor_accesschk"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == ".ex_cod"
        )
}

// rule fsg_accesschk{
//     meta: 
//         author = ""
//         version = "6.12"
//         des = "Detection of fsg_accesschk"
//     condition:
//         uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
//             pe.sections[i].name == ""
//         )
//         //khong co name
// }

rule mew_accesschk{
    meta: 
        author = ""
        version = ""
        des = "Detection of mew_accesschk"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == "MEW"or
            pe.sections[i].name == "ÒuÛ$ëÔ"
        )
}

rule molebox_accesschk{
    meta: 
        author = ""
        version = "6.12"
        des = "Detection of molebox_accesschk"
    condition:
        uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections - 1): (
            pe.sections[i].name == "0"or
            pe.sections[i].name == "1"or
            pe.sections[i].name == "2"or
            pe.sections[i].name == "3"or
            pe.sections[i].name == "4"or
            pe.sections[i].name == "5"or
            pe.sections[i].name == "6"or
            pe.sections[i].name == "7"
        )
}