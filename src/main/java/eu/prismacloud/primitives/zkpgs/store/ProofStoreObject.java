package eu.prismacloud.primitives.zkpgs.store;

import eu.prismacloud.primitives.zkpgs.util.URN;
import java.util.HashMap;
import java.util.Map;
/** Storage class for storing objects that pertain a particular proof */
public class ProofStoreObject implements Storable {
  /** storage for objects required for SPKs */
  private static Map<URN, ProofObject> store;

  private ProofStoreObject() {}

  public static void createProofStore() {
    store = new HashMap<URN, ProofObject>();
  }

  @Override
  public void store(URN urn, ProofObject proofObject) {
    store.put(urn, proofObject);
  }

  @Override
  public ProofObject retrieve(URN urn) {
    return store.get(urn);
  }
}
