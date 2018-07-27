package eu.prismacloud.primitives.zkpgs.parameters;

import eu.prismacloud.primitives.zkpgs.util.Assert;

/** The type Graph encoding parameters. */
public class GraphEncodingParameters {
  /** Maximal number of vertices to be encoded */
  private final int l_V;

  /**
   * Reserved bit length for vertex encoding (bit length of the largest encodeable prime
   * representative)
   */
  private final int lPrime_V;

  /** Maximal number of edges to be encoded */
  private final int l_E;

  /** Maximal number of labels to be encoded */
  private final int l_L;

  /** Reserved bit length for label encoding */
  private final int lPrime_L;

  /**
   * Instantiates a new Graph encoding parameters.
   *
   * @param l_V the maximal number of vertices to be encoded
   * @param lPrime_V the bit length for vertex encoding
   * @param l_E the maximal number of edges to be encoded
   * @param l_L the maximal number of labels to be encoded
   * @param lPrime_L the reserved bit length for label encoding
   * @pre \( l_V != null \and lPrime_V != null \and l_E != null \and l_L != null \and lPrime_L != null\)
   * @post
   */
  public GraphEncodingParameters(int l_V, int lPrime_V, int l_E, int l_L, int lPrime_L) {
    Assert.notNull(l_V, "l_V parameter must not be null");
    Assert.notNull(lPrime_V, "lPrime_V parameter must not be null");
    Assert.notNull(l_E, "l_E parameter must not be null");
    Assert.notNull(l_L, "l_L parameter must not be null");
    Assert.notNull(lPrime_L, "lPrime_L parameter must not be null");

    this.l_V = l_V;
    this.lPrime_V = lPrime_V;
    this.l_E = l_E;
    this.l_L = l_L;
    this.lPrime_L = lPrime_L;
  }

  /**
   * Gets l v.
   *
   * @return the l v
   */
  public int getL_V() {
    return l_V;
  }

  /**
   * Gets l prime v.
   *
   * @return the l prime v
   */
  public int getlPrime_V() {
    return lPrime_V;
  }

  /**
   * Gets l e.
   *
   * @return the l e
   */
  public int getL_E() {
    return l_E;
  }

  /**
   * Gets l l.
   *
   * @return the l l
   */
  public int getL_L() {
    return l_L;
  }

  /**
   * Gets l prime l.
   *
   * @return the l prime l
   */
  public int getlPrime_L() {
    return lPrime_L;
  }
}
