rule MAL_NanoCore_Jan24 {
    meta:
        des = "Detects a NanoCore sample targeting unique strings in an injected/reflected section"

    strings:
        $x1 = "NanoCore Client.exe" fullword ascii
        $x2 = "NanoCore.ClientPlugin" fullword ascii
        $x3 = "NanoCore.ClientPluginHost" fullword ascii
        $x4 = "NanoCore Client" fullword ascii
    condition:
        uint16(0) == 0x5a4d and
        any of them
}