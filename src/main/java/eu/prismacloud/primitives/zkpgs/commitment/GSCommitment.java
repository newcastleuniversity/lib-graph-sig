package eu.prismacloud.primitives.zkpgs.commitment;

import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class GSCommitment implements Serializable {

  private static final long serialVersionUID = -6253701534775989050L;
  private BigInteger m_i;
  private BigInteger r_i;
  private GroupElement baseS;
  private GroupElement R_i;

  private GroupElement commitmentValue;
  private Map<URN, GroupElement> basesR;
  private Map<URN, BigInteger> exponents;
  private BigInteger randomness;
  private GroupElement elementBaseS;
  private BigInteger modN;

  public GSCommitment(
      Map<URN, GroupElement> basesR,
      Map<URN, BigInteger> exponents,
      BigInteger randomness,
      GroupElement elementBaseS,
      BigInteger modN) {

    /** TODO add elementBaseS group element */
    /** TODO change name to elementBaseS */
    /** TODO multiple bases for commitments */
    Assert.notNull(basesR, "base R cannot be null");
    Assert.notNull(exponents, "exponents cannot be null");
    Assert.notNull(randomness, "randomness cannot be null");
    Assert.notNull(elementBaseS, "base S cannot be null");
    Assert.notNull(modN, "modN cannot be null");

    this.basesR = basesR;
    this.exponents = exponents;
    this.randomness = randomness;
    this.elementBaseS = elementBaseS;
    this.modN = modN;
  }

  public GSCommitment(
      GroupElement R_i, BigInteger m_i, BigInteger r_i, GroupElement baseS, BigInteger modN) {

    this.R_i = R_i;
    this.m_i = m_i;
    this.r_i = r_i;
    this.baseS = baseS;
    this.modN = modN;
    this.commitmentValue = (R_i.modPow(m_i)).multiply(baseS.modPow(r_i));
    
    this.exponents = new HashMap<URN, BigInteger>();
    this.exponents.put(URN.createZkpgsURN("commitment.exponent.m"), m_i);
    
    this.randomness = r_i;
    
    this.basesR = new HashMap<URN, GroupElement>();
    basesR.put(URN.createZkpgsURN("commitment.base.R"), R_i);
  }

  public GSCommitment(GroupElement commitmentValue) {
    this.commitmentValue = commitmentValue;
  }

  //  public BigInteger commit() {
  //
  //    BigInteger baseResult = CryptoUtilsFacade.computeMultiBaseExMap(basesR, exponents, modN);
  //
  //    commitmentValue = baseResult.multiply(elementBaseS.modPow(randomness, modN).getValue());
  //
  //    return commitmentValue;
  //  }
  
  public static GSCommitment createCommitment(BigInteger m, GroupElement baseR, ExtendedPublicKey epk) {
	  
	  KeyGenParameters keyGenParameters = epk.getPublicKey().getKeyGenParameters();
	  
	  
	  // GroupElement message = baseR.modPow(m);
	  
	  // Establishing blinding
	  BigInteger r = CryptoUtilsFacade.computeRandomNumberMinusPlus(
		        keyGenParameters.getL_n() + keyGenParameters.getL_statzk());
	  // GroupElement blinding = epk.getPublicKey().getBaseS().modPow(r);
	  
	  // GroupElement commitmentValue = message.multiply(blinding);
	  
	  return new GSCommitment(baseR, m, r, epk.getPublicKey().getBaseS(), epk.getPublicKey().getModN());
  }

  public void setCommitmentValue(GroupElement commitmentValue) {
    this.commitmentValue = commitmentValue;
  }

  public GroupElement getCommitmentValue() {
	  if (this.commitmentValue == null) {
		  if (R_i != null && m_i != null && r_i != null && baseS != null) {
			  this.commitmentValue = (R_i.modPow(m_i)).multiply(baseS.modPow(r_i));
		  } 
//		  else if (basesR != null && exponents != null && randomness != null && baseS != null) { 
//			  
//		  }
	  }
    return commitmentValue;
  }

  public Map<URN, GroupElement> getBasesR() {
    return basesR;
  }

  public Map<URN, BigInteger> getExponents() {
    return exponents;
  }

  public BigInteger getRandomness() {
    return randomness;
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
  //    GSCommitment that = (GSCommitment) o;
  //
  //    if (this.m_i != null ? !this.m_i.equals(that.m_i) : that.m_i != null) {
  //      return false;
  //    }
  //    if (this.r_i != null ? !this.r_i.equals(that.r_i) : that.r_i != null) {
  //      return false;
  //    }
  //    if (this.baseS != null ? !this.baseS.equals(that.baseS) : that.baseS != null) {
  //      return false;
  //    }
  //    if (this.R_i != null ? !this.R_i.equals(that.R_i) : that.R_i != null) {
  //      return false;
  //    }
  //    if (this.getCommitmentValue() != null
  //        ? !this.getCommitmentValue().equals(that.getCommitmentValue())
  //        : that.getCommitmentValue() != null) {
  //      return false;
  //    }
  //    if (this.getBasesR() != null
  //        ? !this.getBasesR().equals(that.getBasesR())
  //        : that.getBasesR() != null) {
  //      return false;
  //    }
  //    if (this.getExponents() != null
  //        ? !this.getExponents().equals(that.getExponents())
  //        : that.getExponents() != null) {
  //      return false;
  //    }
  //    if (this.getRandomness() != null
  //        ? !this.getRandomness().equals(that.getRandomness())
  //        : that.getRandomness() != null) {
  //      return false;
  //    }
  //    if (this.elementBaseS != null
  //        ? !this.elementBaseS.equals(that.elementBaseS)
  //        : that.elementBaseS != null) {
  //      return false;
  //    }
  //    return this.modN != null ? this.modN.equals(that.modN) : that.modN == null;
  //  }
  //
  //  @Override
  //  public int hashCode() {
  //    int result = this.m_i != null ? this.m_i.hashCode() : 0;
  //    result = 31 * result + (this.r_i != null ? this.r_i.hashCode() : 0);
  //    result = 31 * result + (this.baseS != null ? this.baseS.hashCode() : 0);
  //    result = 31 * result + (this.R_i != null ? this.R_i.hashCode() : 0);
  //    result =
  //        31 * result
  //            + (this.getCommitmentValue() != null ? this.getCommitmentValue().hashCode() : 0);
  //    result = 31 * result + (this.getBasesR() != null ? this.getBasesR().hashCode() : 0);
  //    result = 31 * result + (this.getExponents() != null ? this.getExponents().hashCode() : 0);
  //    result = 31 * result + (this.getRandomness() != null ? this.getRandomness().hashCode() : 0);
  //    result = 31 * result + (this.elementBaseS != null ? this.elementBaseS.hashCode() : 0);
  //    result = 31 * result + (this.modN != null ? this.modN.hashCode() : 0);
  //    return result;
  //  }

  @Override
  public String toString() {
    final StringBuilder sb =
        new StringBuilder("eu.prismacloud.primitives.zkpgs.commitment.GSCommitment{");
    sb.append("m_i=").append(m_i);
    sb.append(", r_i=").append(r_i);
    sb.append(", baseS=").append(baseS);
    sb.append(", R_i=").append(R_i);
    sb.append(", commitmentValue=").append(commitmentValue);
    sb.append(", basesR=").append(basesR);
    sb.append(", exponents=").append(exponents);
    sb.append(", randomness=").append(randomness);
    sb.append(", elementBaseS=").append(elementBaseS);
    sb.append(", modN=").append(modN);
    //    sb.append(", commit=").append(commit());
    sb.append('}');
    return sb.toString();
  }
}
