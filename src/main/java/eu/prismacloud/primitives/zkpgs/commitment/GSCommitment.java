package eu.prismacloud.primitives.zkpgs.commitment;

import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.Map;

public class GSCommitment {

  private BigInteger m_i;
  private BigInteger r_i1;
  private BigInteger s;
  private BigInteger R_i;

  private BigInteger commitmentValue;
  private Map<URN, GroupElement> basesR;
  private Map<URN, BigInteger> exponents;
  private BigInteger randomness;
  private GroupElement baseS;
  private BigInteger modN;

  public GSCommitment(
      Map<URN, GroupElement> basesR,
      Map<URN, BigInteger> exponents,
      BigInteger randomness,
      GroupElement baseS,
      BigInteger modN) {

    /** TODO add baseS group element */
    /** TODO change name to baseS */
    /** TODO multiple bases for commitments */
    Assert.notNull(basesR, "base R cannot be null");
    Assert.notNull(exponents, "exponents cannot be null");
    Assert.notNull(randomness, "randomness cannot be null");
    Assert.notNull(baseS, "base S cannot be null");
    Assert.notNull(modN, "modN cannot be null");

    this.basesR = basesR;
    this.exponents = exponents;
    this.randomness = randomness;
    this.baseS = baseS;
    this.modN = modN;
  }

  public GSCommitment(BigInteger R_i, BigInteger m_i, BigInteger r_i1, BigInteger S, BigInteger modN) {

    this.R_i = R_i;
    this.m_i = m_i;
    this.r_i1 = r_i1;
    s = S;
    this.modN = modN;
  }

  public BigInteger commit() {

    BigInteger baseResult = CryptoUtilsFacade.computeMultiBaseEx(basesR,exponents , modN);


    commitmentValue = baseResult.multiply(baseS.modPow(randomness, modN).getValue());
    return commitmentValue;
  }

  public BigInteger getCommitmentValue() {
    return this.commitmentValue;
  }

  public Map<URN, GroupElement> getBasesR() {
    return this.basesR;
  }

  public Map<URN, BigInteger> getExponents() {
    return this.exponents;
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
    if (!this.getBasesR().equals(that.getBasesR())) {
      return false;
    }
    if (!this.getExponents().equals(that.getExponents())) {
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
    result = (31 * result) + this.getBasesR().hashCode();
    result = (31 * result) + this.getExponents().hashCode();
    result = (31 * result) + this.getRandomness().hashCode();
    result = (31 * result) + this.baseS.hashCode();
    result = (31 * result) + this.modN.hashCode();
    return result;
  }

  @Override
  public String toString() {
    final StringBuilder sb =
        new StringBuilder("eu.prismacloud.primitives.zkpgs.commitment.GSCommitment{");
    sb.append("commitmentValue=").append(commitmentValue);
    sb.append(", basesR=").append(basesR);
    sb.append(", exponents=").append(exponents);
    sb.append(", randomness=").append(randomness);
    sb.append(", baseS=").append(baseS);
    sb.append(", modN=").append(modN);
    sb.append(", commit=").append(commit());
    sb.append('}');
    return sb.toString();
  }
}
