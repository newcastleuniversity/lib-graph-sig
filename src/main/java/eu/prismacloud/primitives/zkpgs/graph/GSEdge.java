package eu.prismacloud.primitives.zkpgs.graph;

/** Representing a edge message in a graph signature. */
public class GSEdge {

  private GSVertex m_i;
  private GSVertex m_j;

  public GSVertex getM_i() {
    return m_i;
  }

  public GSVertex getM_j() {
    return m_j;
  }

  public void GSEdge(GSVertex m_i, GSVertex m_j) {

    this.m_i = m_i;
    this.m_j = m_j;
  }
}
