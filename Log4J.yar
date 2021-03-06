rule Log4J {
   meta:
      description = "Detect Log4J attack in your system"
      license = "Will be comming Hakankkk.lic, but now it is free to use"
      author = "Hakan Kilic"
      reference = "First Trials"
      date = "2021-12-10"
      hash1 = "-"
    strings:
      $a = "jndi:ldap:"
      $b = "jndi:ldaps:"
      $c = "jndi:rmi:"
      $d = "jndi:dns:"
      $e = "jbdi:ldap://...\\/a"
      $f = "jbdi:ldaps://...\\/a"
      $g = "log4j.logger.java"
      $h = "jndi:$\\{lower:l\\}$\\{lower:d\\}"
      $i = "logger.error(jindi)"
      $j = "am5kaTpsZGFwOg"
      $k = "am5kaTpsZGFwczo"
      $l = "am5kaTpybWk6"
      $m = "kaTpkbnM6"
    condition:
       1 of them

    }
