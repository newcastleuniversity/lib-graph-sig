package eu.prismacloud.primitives.zkpgs.store;

import eu.prismacloud.primitives.zkpgs.util.URN;

public interface Storable {
  void store(URN urn, ProofObject proofObject);

  ProofObject retrieve(URN urn);
}
    