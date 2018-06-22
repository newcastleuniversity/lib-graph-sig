package eu.prismacloud.primitives.zkpgs.util.crypto;

import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import java.math.BigInteger;
import java.util.List;

/**
 * Class that represents an element in Quadratic Residues group without knowing the factorization of
 * modulus N.
 */
public class QRElementN extends QRElement {
  private QRGroupN qrGroup;
  private BigInteger number;

  /**
   * Instantiates a new Qr element n.
   *
   * @param qrGroup the qr group
   * @param number the number
   */
  public QRElementN(final QRGroupN qrGroup, final BigInteger number) {

    super(qrGroup, number);
    this.qrGroup = qrGroup;
    this.number = number;
  }

  /**
   * Instantiates a new Qr element n.
   *
   * @param value the value
   */
  public QRElementN(final BigInteger value) {
    super(value);
    this.number = value;
  }

  /**
   * Instantiates a new Qr element n.
   *
   * @param group the group
   * @param value the value
   */
  public QRElementN(final Group group, final BigInteger value) {
    super(group, value);
  }

  @Override
  public Group getGroup() {
    return qrGroup;
  }

  @Override
  public BigInteger getValue() {
    return number;
  }

  @Override
  public BigInteger multiply(BigInteger val) {
    return super.multiply(val);
  }

  @Override
  public GroupElement modPow(BigInteger exponent, BigInteger modN) {
    return super.modPow(exponent, modN);
  }

  /**
   * Multi base exp big integer.
   *
   * @param bases the bases
   * @param exponents the exponents
   * @return the big integer
   */
  public BigInteger multiBaseExp(List<BigInteger> bases, List<BigInteger> exponents) {
    return CryptoUtilsFacade.computeMultiBaseEx(bases, exponents, this.qrGroup.getModulus());
  }

  @Override
  public String toString() {
    final StringBuilder sb =
        new StringBuilder("eu.prismacloud.primitives.zkpgs.util.crypto.QRElementN{");
    sb.append("qrGroup=").append(qrGroup);
    sb.append(", number=").append(number);
    sb.append(", group=").append(getGroup());
    sb.append(", value=").append(getValue());
    sb.append('}');
    return sb.toString();
  }
}
