rule Recon_Finder {
   meta:
      description = "Recon Tool detection rule"
      license = "Will be comming Hakankkk.lic, but now it is free to use"
      author = "Hakan Kilic"
      reference = "First Trials"
      date = "2021-10-21"
      hash1 = "-"
    strings:
      $a = "Unable to set socket to sniff"
      $b = "except Sqlmap"
      $c = "NBTScanner!y&"
      $d = "Scan Ports"
      $e = "Open ports are"
      $f = "WSocketResolveHost: Cannot convert host address"
      $g = "Syn Scan Port"
      $h = "scan.bat"
    condition:
      1 of them
    }


