package eu.prismacloud.primitives.zkpgs;

/** Enum used by EnabledOnSuite junit extension for executing test suites */
public enum GSSuite {
  RECIPIENT_SIGNER,
  PROVER_VERIFIER,
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
