rule Log4J {
   meta:
      description = "Detect Log4J attack in your system"
      license = "Will be comming Hakankkk.lic, but now it is free to use"
      author = "Hakan Kilic"
      reference = "First Trials"
      date = "2021-12-10"
      hash1 = "-"
    strings:
      $a = "jndi:ldap:
      $b = "jndi:ldaps:"
      $c = "jndi:rmi:"
      $d = "jndi:dns:"
      $e = "jbdi:ldap://...\\/a"
      $f = "jbdi:ldaps://...\\/a"
    
    condition:
       1 of them

    }
