package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;
import java.util.ArrayList;

/** Quadratic Residue Group where we don't know the modulus factorization in \(Z^*_p \) */
public final class QRGroupN extends Group {

  private final BigInteger modulus;
  private QRElementN generator;
  private ArrayList<GroupElement> groupElements;

  public QRGroupN(final BigInteger modulus) {
    this.modulus = modulus;
  }

  @Override
  public BigInteger getOrder() {
    throw new RuntimeException("Order must not be known");
  }

  @Override
  public GroupElement getGenerator() {
    return this.generator;
  }

  public QRElementN createGenerator() {
    return this.generator =
        new QRElementN(this, CryptoUtilsFacade.computeQRNGenerator(this.modulus));
  }

  @Override
  public GroupElement createElement() {
    QRElement qrElement = new QRElementN(this, CryptoUtilsFacade.computeQRNElement(this.modulus));

    this.groupElements.add(qrElement);

    return qrElement;
  }

  @Override
  public GroupElement createElement(GroupElement s) {
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

  /**
   * Check if an element \( x \in Z^*_p \) is a quadratic residue.
   *
   * @param x the number to check for quadratic residuosity
   * @return the boolean
   */
  public boolean isQR(final BigInteger x) {

    return JacobiSymbol.computeJacobiSymbol(x, this.modulus) == 1;
  }
}
