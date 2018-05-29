package eu.prismacloud.primitives.grs;

import eu.prismacloud.primitives.grs.graph.GSEdge;
import eu.prismacloud.primitives.grs.graph.GSVertex;
import eu.prismacloud.primitives.grs.keys.ExtendedPrivateKey;
import eu.prismacloud.primitives.grs.keys.ExtendedPublicKey;
import java.math.BigInteger;
import java.util.Iterator;

/** The graph signature includes the methods for randomization, vertex and edge iterators. */
public class GraphSignature {

  private ExtendedPublicKey extendedPublicKey;
  private ExtendedPrivateKey extendedPrivateKey;

  public void GraphSignature() {}

  public BigInteger getA() {
    return null;
  }

  public BigInteger getE() {
    return null;
  }

  public BigInteger getV() {
    return null;
  }

  public GraphSignature randomize() {
    return new GraphSignature();
  }

  public BigInteger getBasesPermutation() {
    return null;
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
