package eu.prismacloud.primitives.zkpgs.store;

import java.util.ArrayList;
import java.util.List;

public class ProofObject {
  List<Object> proofObjects = new ArrayList<>();

  public ProofObject(final List<Object> proofObjects) {

    this.proofObjects = proofObjects;
  }

  public List<Object> getProofObjects() {
    return this.proofObjects;
  }
}
