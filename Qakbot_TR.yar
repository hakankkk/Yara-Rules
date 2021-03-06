
rule Qakbot_TR {
   meta:
      description = "Detects Qakbot Trojan in your system"
      license = "Will be comming Hakankkk.lic, but now it is free to use"
      author = "Hakan Kilic"
      reference = "First Trials"
      date = "2021-12-11"
      hash1 = "-"
    strings:
      $a1 = "3084898addae403f58054a7965db5900"
      $a2 = "f09a7d035b4af771d3e4394cde8bc95c"
      $a3 = "a9960e9b60051278fadda41fc4f87d36"
      $b1 = "https://jvtransportes.log.br" fullword ascii
      $b2 = "https://dimenew.com.br" fullword ascii
      $b3 = "https://sabitblog.com/7ihEMh6PKKX" fullword ascii
      $b4 = "https://leadindia.org"
      $b5 = "https://chromedomemotorcycleproducts.com"
      $b6 = "https://chromedomemp.com"
    condition:
      ( 1 of (uint16(0) == 0x504b0304 and filesize < 30KB and filesize > 10MB and 1 of ( hash.md5(0, filesize) == $a* )) or $b*
      )
    }
