package uk.ac.ncl.cascade.zkpgs.prover;

import java.io.Serializable;
import java.util.Map;

import uk.ac.ncl.cascade.zkpgs.store.URN;

/** Class encapsulating the elements of a proof signature */
public class ProofSignature implements Serializable {

  private static final long serialVersionUID = 760605145677522661L;
  private final Map<URN, Object> proofSignatureElements;

  public ProofSignature(Map<URN, Object> proofSignatureElements) {
    this.proofSignatureElements = proofSignatureElements;
  }

  public Map<URN, Object> getProofSignatureElements() {
    return this.proofSignatureElements;
  }

  public Object get(String urnkey) {
    URN key = URN.createURN(URN.getZkpgsNameSpaceIdentifier(), urnkey);
    return proofSignatureElements.get(key);
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("eu.prismacloud.primitives.zkpgs.prover.ProofSignature{");
    sb.append("serialVersionUID=").append(serialVersionUID);
    sb.append(", proofSignatureElements=").append(proofSignatureElements);
    sb.append('}');
    return sb.toString();
  }
}
