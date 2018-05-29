package eu.prismacloud.primitives.zkpgs.keys;

import java.math.BigInteger;
import java.util.Vector;

public class ExtendedPublicKey {
  ExtendedPublicKey publicKey;
  Vector<BigInteger> vertexBases;
  Vector<BigInteger> edgeBases;

  public ExtendedPublicKey getPublicKey() {
    return publicKey;
  }

  public ExtendedPrivateKey getPrivateKey() {
    return null;
  }

  public Vector<BigInteger> getVertexBases() {
    return vertexBases;
  }

  public Vector<BigInteger> getEdgeBases() {
    return edgeBases;
  }
}
