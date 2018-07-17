package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.util.URN;
import java.io.Serializable;
import java.util.Map;

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
}
