package eu.prismacloud.primitives.zkpgs.commitment;

import eu.prismacloud.primitives.zkpgs.util.Assert;
import java.math.BigInteger;

public class GSCommitment { // implements ICommitment {

  private BigInteger commitmentValue;
  private final BigInteger baseR;
  private final BigInteger exponent;
  private final BigInteger randomness;
  private final BigInteger baseS;
  private final BigInteger modN;

  public GSCommitment(
      BigInteger baseR,
      BigInteger exponent,
      BigInteger randomness,
      BigInteger baseS,
      BigInteger modN) {

    /** TODO add baseS group element */
    /** TODO change name to baseS */
    /** TODO multiple bases for commitments */
    Assert.notNull(baseR, "base R cannot be null");
    Assert.notNull(exponent, "exponent cannot be null");
    Assert.notNull(randomness, "randomness cannot be null");
    Assert.notNull(baseS, "base S cannot be null");
    Assert.notNull(modN, "modN cannot be null");

    this.baseR = baseR;
    this.exponent = exponent;
    this.randomness = randomness;
    this.baseS = baseS;
    this.modN = modN;
  }

  public BigInteger commit() {

    commitmentValue = baseR.modPow(exponent, modN).multiply(baseS.modPow(randomness, modN));
    return commitmentValue;
  }

  public BigInteger getCommitmentValue() {
    return this.commitmentValue;
  }

  public BigInteger getBaseR() {
    return this.baseR;
  }

  public BigInteger getExponent() {
    return this.exponent;
  }

  public BigInteger getRandomness() {
    return this.randomness;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || this.getClass() != o.getClass()) {
      return false;
    }

    GSCommitment that = (GSCommitment) o;

    if (!this.getCommitmentValue().equals(that.getCommitmentValue())) {
      return false;
    }
    if (!this.getBaseR().equals(that.getBaseR())) {
      return false;
    }
    if (!this.getExponent().equals(that.getExponent())) {
      return false;
    }
    if (!this.getRandomness().equals(that.getRandomness())) {
      return false;
    }
    if (!this.baseS.equals(that.baseS)) {
      return false;
    }
    return this.modN.equals(that.modN);
  }

  @Override
  public int hashCode() {
    int result = this.getCommitmentValue().hashCode();
    result = 31 * result + this.getBaseR().hashCode();
    result = 31 * result + this.getExponent().hashCode();
    result = 31 * result + this.getRandomness().hashCode();
    result = 31 * result + this.baseS.hashCode();
    result = 31 * result + this.modN.hashCode();
    return result;
  }

  @Override
  public String toString() {
    final StringBuilder sb =
        new StringBuilder("eu.prismacloud.primitives.zkpgs.commitment.GSCommitment{");
    sb.append("commitmentValue=").append(commitmentValue);
    sb.append(", baseR=").append(baseR);
    sb.append(", exponent=").append(exponent);
    sb.append(", randomness=").append(randomness);
    sb.append(", baseS=").append(baseS);
    sb.append(", modN=").append(modN);
    sb.append(", commit=").append(commit());
    sb.append('}');
    return sb.toString();
  }
}
