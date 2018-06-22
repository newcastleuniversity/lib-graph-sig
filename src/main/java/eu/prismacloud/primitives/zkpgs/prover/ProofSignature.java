package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.Map;

/** Class encapsulating the elements of a proof signature */
public class ProofSignature {
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

  /** TODO fix get methods for proof signature elements */
  public BigInteger getZ() {
    return null;
  }

  public BigInteger getC() {
    return null;
  }

  public BigInteger getS() {
    return null;
  }

  public BigInteger getHatr_Z() {
    return null;
  }

  public BigInteger getN() {
    return null;
  }

  public BigInteger getR() {
    return null;
  }

  public BigInteger getHatr() {
    return null;
  }

  public BigInteger getR_0() {
    return null;
  }

  public BigInteger getHatr_0() {
    return null;
  }

  public Map<String, BigInteger> getVertexBases() {
    return null;
  }

  public Map<String, BigInteger> getEdgeBases() {
    return null;
  }

  public Map<String, BigInteger> getEdgeResponses() {
    return null;
  }

  public Map<String, BigInteger> getVertexResponses() {
    return null;
  }
}
