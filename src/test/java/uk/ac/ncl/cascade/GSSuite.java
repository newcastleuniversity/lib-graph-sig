package uk.ac.ncl.cascade;

/** Enum used by EnabledOnSuite junit extension for executing test suites */
public enum GSSuite {
  RECIPIENT_SIGNER,
  BCRECIPIENT_BCSIGNER,
  PROVER_VERIFIER,
  BINDING,
  GSCLIENT_GSSERVER;

  public static boolean suiteExists(String name) {
    for (GSSuite suite : GSSuite.values()) {
      if (suite.name().equals(name)) {
        return true;
      }
    }
    return false;
  }
}
