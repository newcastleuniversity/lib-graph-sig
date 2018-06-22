package eu.prismacloud.primitives.zkpgs;

import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPrivateKey;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import java.math.BigInteger;
import java.util.Iterator;

/**
 * The graph signature includes the methods for blinding a given graph signature, vertex and edge
 * iterators.
 */
public class GraphSignature {

  private ExtendedPublicKey extendedPublicKey;
  private ExtendedPrivateKey extendedPrivateKey;
  private BigInteger A;
  private BigInteger e;
  private BigInteger v;

  public void GraphSignature() {}

  public BigInteger getA() {
    return this.A;
  }

  public BigInteger getE() {
    return this.e;
  }

  public BigInteger getV() {
    return this.v;
  }

  public GraphSignature blindGS(GraphSignature gs) {
    return new GraphSignature();
  }

  public BigInteger getBasesPermutation() {
    return null;
  }

  public BigInteger computeA() {
    CryptoUtilsFacade.computeA();
    return BigInteger.valueOf(2);
  }

  public Iterator<GSVertex> getVerticesIterator() {
    return new Iterator<GSVertex>() {
      @Override
      public boolean hasNext() {
        return false;
      }

      @Override
      public GSVertex next() {
        return null;
      }
    };
  }

  public Iterator<GSEdge> getEdgesIterator() {
    return new Iterator<GSEdge>() {

      @Override
      public boolean hasNext() {
        return false;
      }

      @Override
      public GSEdge next() {
        return null;
      }
    };
  }
}
