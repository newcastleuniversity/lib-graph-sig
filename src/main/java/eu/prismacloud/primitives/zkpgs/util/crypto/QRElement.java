package eu.prismacloud.primitives.zkpgs.util.crypto;

import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/** Element of Quadratic Residue Group. */
public class QRElement extends GroupElement {
  private Group group;

  private final BigInteger value;

  public QRElement(final BigInteger value) {
    this.value = value;
  }

  public QRElement(final Group group, final BigInteger value) {
    this.group = group;
    this.value = value;
  }

  @Override
  public BigInteger getValue() {
    return value;
  }

  public BigInteger nextProbablePrime() {
    return value.nextProbablePrime();
  }

  public BigInteger add(BigInteger val) {
    return value.add(val);
  }

  public BigInteger subtract(BigInteger val) {
    return value.subtract(val);
  }

  public QRElement multiply(QRElement val) {
    return new QRElement(value).multiply(val);
  }

  @Override
  public BigInteger multiBaseExp(List<BigInteger> bases, List<BigInteger> exponents) {
    return CryptoUtilsFacade.computeMultiBaseEx(bases, exponents, this.group.getModulus());
  }

  public BigInteger multiBaseExp(Map<URN, GroupElement> bases, Map<URN, BigInteger> exponents) {
    return CryptoUtilsFacade.computeMultiBaseEx(bases, exponents, this.group.getModulus());
  }

  @Override
  public QRElement multiply(BigInteger val) {
    return new QRElement(value.multiply(val));
  }

  public BigInteger divide(BigInteger val) {
    return value.divide(val);
  }

  public BigInteger[] divideAndRemainder(BigInteger val) {
    return value.divideAndRemainder(val);
  }

  public BigInteger remainder(BigInteger val) {
    return value.remainder(val);
  }

  public BigInteger gcd(BigInteger val) {
    return value.gcd(val);
  }

  public BigInteger abs() {
    return value.abs();
  }

  public BigInteger negate() {
    return value.negate();
  }

  public int signum() {
    return value.signum();
  }

  public BigInteger mod(BigInteger m) {
    return value.mod(m);
  }

  @Override
  public QRElementPQ modPow(BigInteger exponent, BigInteger modN) {
    return new QRElementPQ(value.modPow(exponent, modN));
  }

  public BigInteger modInverse(BigInteger m) {
    return value.modInverse(m);
  }

  public int getLowestSetBit() {
    return value.getLowestSetBit();
  }

  public int bitLength() {
    return value.bitLength();
  }

  public int bitCount() {
    return value.bitCount();
  }

  public boolean isProbablePrime(int certainty) {
    return value.isProbablePrime(certainty);
  }

  public int compareTo(BigInteger val) {
    return value.compareTo(val);
  }

  @Override
  public boolean equals(Object x) {
    return value.equals(x);
  }

  public BigInteger min(BigInteger val) {
    return value.min(val);
  }

  public BigInteger max(BigInteger val) {
    return value.max(val);
  }

  @Override
  public int hashCode() {
    return value.hashCode();
  }

  public String toString(int radix) {
    return value.toString(radix);
  }

  @Override
  public String toString() {
    return value.toString();
  }

  public byte[] toByteArray() {
    return value.toByteArray();
  }

  @Override
  public Group getGroup() {
    return group;
  }
}
