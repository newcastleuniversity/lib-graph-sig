package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.Map;

public class ExtendedPrivateKey {

  private final SignerPrivateKey signerPrivateKey;
  private Map<URN, BigInteger> discLogOfVertexBases;
  private Map<URN, BigInteger> discLogOfEdgeBases;

  public ExtendedPrivateKey(
      SignerPrivateKey signerPrivateKey,
      Map<URN, BigInteger> discLogOfVertexBases,
      Map<URN, BigInteger> discLogOfEdgeBases) {

    this.signerPrivateKey = signerPrivateKey;
    this.discLogOfVertexBases = discLogOfVertexBases;
    this.discLogOfEdgeBases = discLogOfEdgeBases;
  }

  public Map<URN, BigInteger> getDiscLogOfVertexBases() {
    return discLogOfVertexBases;
  }

  public Map<URN, BigInteger> getDiscLogOfEdgesBases() {
    return discLogOfEdgeBases;
  }

  public SignerPrivateKey getPrivateKey() {
    return this.signerPrivateKey;
  }
}
