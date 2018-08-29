package eu.prismacloud.primitives.zkpgs.graph;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/** A graph vertex for graph representation. */
public class GSVertex {
  private List<String> labels = new ArrayList<>();
  private String id;
  private BigInteger vertexPrimeRepresentative;
  private List<BigInteger> labelPrimeRepresentatives = new ArrayList<>();

  public GSVertex(final String id, final List<String> labels) {
    this.id = id;
    this.labels = labels;
  }

  public List<String> getLabels() {
    return labels;
  }

  public void setLabels(List<String> labels) {
    this.labels = labels;
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public List<BigInteger> getLabelPrimeRepresentatives() {
    return labelPrimeRepresentatives;
  }

  public void setLabelRepresentatives(List<BigInteger> labelPrimeRepresentatives) {
    this.labelPrimeRepresentatives = labelPrimeRepresentatives;
  }

  public BigInteger getVertexRepresentative() {
    return vertexPrimeRepresentative;
  }

  public void setVertexRepresentative(BigInteger vertexPrimeRepresentative) {
    this.vertexPrimeRepresentative = vertexPrimeRepresentative;
  }

  //  @Override
  //  public boolean equals(Object o) {
  //    if (this == o) {
  //      return true;
  //    }
  //    if (o == null || this.getClass() != o.getClass()) {
  //      return false;
  //    }
  //    GSVertex gsVertex = (GSVertex) o;
  //    return Objects.equals(this.getLabels(), gsVertex.getLabels())
  //        && Objects.equals(this.getId(), gsVertex.getId())
  //        && Objects.equals(this.getCountry(), gsVertex.getCountry())
  //        && Objects.equals(
  //            this.getVertexPrimeRepresentative(), gsVertex.getVertexPrimeRepresentative())
  //        && Objects.equals(
  //            this.getLabelPrimeRepresentatives(), gsVertex.getLabelPrimeRepresentatives());
  //  }
  //
  //  @Override
  //  public int hashCode() {
  //    int result = this.getLabels().hashCode();
  //    result = 31 * result + this.getId().hashCode();
  //    result = 31 * result + this.getCountry().hashCode();
  //    result = 31 * result + this.getVertexPrimeRepresentative().hashCode();
  //    result = 31 * result + this.getLabelPrimeRepresentatives().hashCode();
  //    return result;
  //  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("eu.prismacloud.primitives.zkpgs.graph.GSVertex{");
    sb.append("labels=").append(labels);
    sb.append(", id='").append(id).append('\'');
    sb.append(", vertexPrimeRepresentative=").append(vertexPrimeRepresentative);
    sb.append(", labelPrimeRepresentatives=").append(labelPrimeRepresentatives);
    sb.append('}');
    return sb.toString();
  }
}
