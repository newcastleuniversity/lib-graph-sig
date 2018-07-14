package eu.prismacloud.primitives.zkpgs.graph;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.jgrapht.graph.DefaultEdge;

/** Representing a edge in a graph. */
public class GSEdge extends DefaultEdge {

  private GSVertex e_i;
  private GSVertex e_j;
  private List<BigInteger> labelRepresentatives = new ArrayList<>();
  private List<String> labels = new ArrayList<>();

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

  public List<BigInteger> getLabelRepresentatives() {
    return labelRepresentatives;
  }

  public void setLabelRepresentatives(List<BigInteger> labelRepresentatives) {
    this.labelRepresentatives = labelRepresentatives;
  }

  public List<String> getLabels() {
    return labels;
  }

  public void setLabels(List<String> labels) {
    this.labels = labels;
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
  //    return this.getLabelRepresentatives().equals(gsEdge.getLabelRepresentatives());
  //  }
  //
  //  @Override
  //  public int hashCode() {
  //    int result = this.getE_i().hashCode();
  //    result = 31 * result + this.getE_j().hashCode();
  //    result = 31 * result + this.getLabelRepresentatives().hashCode();
  //    return result;
  //  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("eu.prismacloud.primitives.zkpgs.graph.GSEdge{");
    sb.append("e_i=").append(e_i);
    sb.append(", e_j=").append(e_j);
    sb.append(", labelRepresentatives=").append(labelRepresentatives);
    sb.append(", labels=").append(labels);
    sb.append('}');
    return sb.toString();
  }
}
