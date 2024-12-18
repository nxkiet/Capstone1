rule MAL_QuasarRAT_Jan24 {
    meta:
        des = "Detects active QuasarRAT samples targeting observed namespaces in decompiled code and process memory"  
   strings:
        $x1 = "Client.exe" wide fullword
        $x2 = "Quasar.Common" ascii
        $x3 = "Quasar.Client" wide ascii

        $namespace1 = "Org.BouncyCastle." wide ascii
        $namespace2 = "Gma.System.MouseKeyHook" ascii
        $namespace3 = "ProtoBuf.Serializers." ascii

    condition:
      1 of ($x*) and all of ($namespace*)
}