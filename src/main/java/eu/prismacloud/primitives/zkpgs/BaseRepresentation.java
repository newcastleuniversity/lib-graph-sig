package eu.prismacloud.primitives.zkpgs;

import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;

/** */
public class BaseRepresentation {

  public enum BASE {
    VERTEX,
    EDGE,
    BASE0
  };

  private final int baseIndex;
  private final BASE baseType;
  private final GroupElement base;
  private  BigInteger exponent;

  public BaseRepresentation(final GroupElement base, final BigInteger exponent, final int baseIndex, BASE baseType) {

    this.base = base;
    this.exponent = exponent;
    this.baseIndex = baseIndex;
    this.baseType = baseType;
  }

  public BaseRepresentation(GroupElement base, int baseIndex, BASE baseType) {

    this.base = base;
    this.baseIndex = baseIndex;
    this.baseType = baseType;
  }

  public int getBaseIndex() {
    return this.baseIndex;
  }

  public void setExponent(BigInteger exponentEncoding) {
    this.exponent = exponentEncoding;
  }

  public GroupElement getBase() {
    return this.base;
  }

  public BigInteger getExponent() {
    return this.exponent;
  }

  public BASE getBaseType() {
    return this.baseType;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(
        "eu.prismacloud.primitives.zkpgs.BaseRepresentation{");
    sb.append("baseIndex=").append(baseIndex);
    sb.append(", baseType=").append(baseType);
    sb.append(", base=").append(base);
    sb.append(", exponent=").append(exponent);
    sb.append('}');
    return sb.toString();
  }
}
