package eu.prismacloud.primitives.zkpgs.graph;

import org.jgrapht.graph.DefaultEdge;

/** Representing a edge message in a graph signature. */
public class GSEdge extends DefaultEdge {

  private GSVertex e_i;
  private GSVertex e_j;
  private String labelRepresentative;

  public GSEdge(GSVertex e_i, GSVertex e_j) {
    this.e_i = e_i;
    this.e_j = e_j;
  }

  public GSVertex getE_i() {
    return e_i;
  }

  public GSVertex getE_j() {
    return e_j;
  }

  public String getLabelRepresentative() {
    return labelRepresentative;
  }

  public void setLabelRepresentative(String labelRepresentative) {
    this.labelRepresentative = labelRepresentative;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("eu.prismacloud.primitives.zkpgs.graph.GSEdge{");
    sb.append("e_i=").append(e_i);
    sb.append(", e_j=").append(e_j);
    sb.append(", labelRepresentative='").append(labelRepresentative).append('\'');
    sb.append('}');
    return sb.toString();
  }

//  @Override
//  public boolean equals(Object o) {
//    if (this == o) {
//      return true;
//    }
//    if (o == null || this.getClass() != o.getClass()) {
//      return false;
//    }
//
//    GSEdge gsEdge = (GSEdge) o;
//
//    if (!this.getE_i().equals(gsEdge.getE_i())) {
//      return false;
//    }
//    if (!this.getE_j().equals(gsEdge.getE_j())) {
//      return false;
//    }
//    return this.getLabelRepresentative().equals(gsEdge.getLabelRepresentative());
//  }
//
//  @Override
//  public int hashCode() {
//    int result = this.getE_i().hashCode();
//    result = 31 * result + this.getE_j().hashCode();
//    result = 31 * result + this.getLabelRepresentative().hashCode();
//    return result;
//  }
}
