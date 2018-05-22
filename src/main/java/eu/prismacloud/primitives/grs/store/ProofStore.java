package eu.prismacloud.primitives.grs.store;

import eu.prismacloud.primitives.grs.utils.URN;
import java.util.HashMap;
import java.util.Map;

public class ProofStore {
  /** storage for objects required for zero knowledge protocolsj*/
  private static Map<URN, ProofObject> store;

  private ProofStore() {}

  public static void createProofStore() {
    store = new HashMap<URN, ProofObject>();
  }

  public static void save(URN urn, ProofObject proofObject) {
    store.put(urn, proofObject);
  }

  public static ProofObject retrieve(URN urn) {
    return store.get(urn);
  }
}
