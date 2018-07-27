package eu.prismacloud.primitives.zkpgs.util.crypto;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.List;

/** Group Element class */
public abstract class GroupElement implements Serializable {
  private static final long serialVersionUID = 3297036609477587811L;

  public abstract Group getGroup();
  
  /**
   * Computes the element order is this order is computable, that is, 
   * the group order and its factorization are known.
   * 
   * Note that computing the element order is intractable 
   * if the factorization of the group order is not known. 
   * Hence, the method will raise an UnsupportedOperationException() if this precondition is not given. 
   * 
   * @return BigInteger element order
   * 
   * @throws UnsupportedOperationException if the computing the element order is intractable.
   */
  public abstract BigInteger getElementOrder() throws UnsupportedOperationException;
  
  /**
   * Checks whether the group/element order is known/computable.
   * 
   * @return true if getElementOrder() can efficiently compute the order.
   */
  public abstract boolean isOrderKnown();
  
  public abstract BigInteger getValue();

  /**
   * Computes an exponentiation with a specified exponent within the group.
   * 
   * @param exponent specifies the exponent within the group
   * @return this.modPow(exponent, this.getGroup().getModulus()
   */
  public abstract GroupElement modPow(BigInteger exponent);

  /**
   * Computes a multiplication with another group element.
   * As a convention, the multiplication operation must ensure that the resulting 
   * product is normalized for the given group, e.g., by a modular reduction.
   * 
   * @param value multiplier
   * @return Group Element product 
   */
  public abstract GroupElement multiply(GroupElement value);
  
  /**
   * 
   * @param bases the bases for the multibase exponentiation
   * @param exponents the exponents for the multibase exponentation
   * @return a GroupElement result of the multibase exponentiation
   */
  public abstract GroupElement multiBaseExp(List<GroupElement> bases, List<BigInteger> exponents);

  public abstract GroupElement modInverse();

  public abstract int bitLength();
  
  public abstract int bitCount();

  public abstract int compareTo(BigInteger val);
  
  public abstract int compareTo(GroupElement val);
}
