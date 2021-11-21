/*

First trials for learning purposes

*/

rule FindMaliciousExe {
   meta:
      description = "Detects suspicious .exe file in your system"
      license = "Will be comming Hakankkk.lic, but now it is free to use"
      author = "Hakan Kilic"
      reference = "First Trials"
      date = "2021-11-21"
      hash1 = "-"
    strings:
      $a = "DLL Injection"
      $b = "Injecting payload"
    condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and filesize > 10MB and 1 of them
      )
    }
