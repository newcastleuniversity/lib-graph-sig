package eu.prismacloud.primitives.zkpgs.util.crypto;

import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import java.math.BigInteger;
import java.util.ArrayList;

/** Quadratic Residue Group where we don't know the modulus factorization in \(Z^*_p \) */
public final class QRGroupN extends QRGroup {

  private final BigInteger modulus;
  private QRElementN generator;
  private ArrayList<GroupElement> groupElements;

  public QRGroupN(final BigInteger modulus) {
    this.modulus = modulus;
  }

  @Override
  public BigInteger getOrder() {
    throw new UnsupportedOperationException("Order not known.");
  }

  @Override
  public GroupElement getGenerator() {
    return this.generator;
  }

  @Override
  public QRElement createGenerator() {
    return this.generator =
        new QRElementN(this, CryptoUtilsFacade.computeQRNGenerator(this.modulus).getValue());
  }

  @Override
  public QRElement createElement() {
    QRElement qrElement = new QRElementN(this, CryptoUtilsFacade.computeQRNElement(this.modulus).getValue());

    this.groupElements.add(qrElement);

    return qrElement;
  }

  @Override
  public QRElement createElement(GroupElement s)
  {
    /** TODO finish implementation for QRGrouN  */
    return null;
  }
  
  @Override
  public GroupElement createElement(BigInteger value) {
  	// TODO Auto-generated method stub
  	return null;
  }

  @Override
  public BigInteger getModulus() {
    return this.modulus;
  }

  @Override
  public boolean isElement(final BigInteger value) {
    return false;
  }

//  /**
//   * Check if an element \( x \in Z^*_p \) is a quadratic residue.
//   *
//   * @param x the number to check for quadratic residuosity
//   * @return the boolean
//   */
//  public boolean isQR(final BigInteger x) {
//
//    return JacobiSymbol.computeJacobiSymbol(x, this.modulus) == 1;
//  }

}
