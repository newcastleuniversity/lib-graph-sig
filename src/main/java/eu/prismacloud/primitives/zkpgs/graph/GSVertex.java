package eu.prismacloud.primitives.zkpgs.graph;

import java.math.BigInteger;
import java.util.Objects;

/** A graph vertex for graph representation. */
public class GSVertex {
  public String getLabel() {
    return label;
  }

  public void setLabel(String label) {
    this.label = label;
  }

  public String label;
  private String id;
  private String country;
  private BigInteger vertexPrimeRepresentative;
  private BigInteger labelPrimeRepresentative;

  public GSVertex(final String id) {
    this(id, "");
  }

  public GSVertex(final String id, final  String country) {
    this.id = id;
    this.country = country;
  }

  public String getCountry() {
    return country;
  }

  public void setCountry(String country) {
    this.country = country;
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public BigInteger getLabelPrimeRepresentative() {
    return labelPrimeRepresentative;
  }

  public void setLabelPrimeRepresentative(BigInteger labelPrimeRepresentative) {
    this.labelPrimeRepresentative = labelPrimeRepresentative;
  }

  public BigInteger getVertexPrimeRepresentative() {
    return vertexPrimeRepresentative;
  }

  public void setVertexPrimeRepresentative(BigInteger vertexPrimeRepresentative) {
    this.vertexPrimeRepresentative = vertexPrimeRepresentative;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || this.getClass() != o.getClass()) {
      return false;
    }
    GSVertex gsVertex = (GSVertex) o;
    return Objects.equals(this.getLabel(), gsVertex.getLabel())
        && Objects.equals(this.getId(), gsVertex.getId())
        && Objects.equals(this.getCountry(), gsVertex.getCountry())
        && Objects.equals(
            this.getVertexPrimeRepresentative(), gsVertex.getVertexPrimeRepresentative())
        && Objects.equals(
            this.getLabelPrimeRepresentative(), gsVertex.getLabelPrimeRepresentative());
  }

  @Override
  public int hashCode() {
    int result = this.getLabel().hashCode();
    result = 31 * result + this.getId().hashCode();
    result = 31 * result + this.getCountry().hashCode();
    result = 31 * result + this.getVertexPrimeRepresentative().hashCode();
    result = 31 * result + this.getLabelPrimeRepresentative().hashCode();
    return result;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(
        "eu.prismacloud.primitives.zkpgs.graph.GSVertex{");
    sb.append("label='").append(label).append('\'');
    sb.append(", id='").append(id).append('\'');
    sb.append(", country='").append(country).append('\'');
    sb.append(", vertexPrimeRepresentative=").append(vertexPrimeRepresentative);
    sb.append(", labelPrimeRepresentative=").append(labelPrimeRepresentative);
    sb.append('}');
    return sb.toString();
  }
}
