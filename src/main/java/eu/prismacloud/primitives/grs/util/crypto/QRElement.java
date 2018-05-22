package eu.prismacloud.primitives.grs.util.crypto;

import java.math.BigInteger;

/** element of Quadratic Residue Group */
public abstract class QRElement extends GroupElement {
  private Group group;

  private final BigInteger value;

  public QRElement(final BigInteger value) {
    this.value = value;
  }

  public QRElement(final Group group, final BigInteger value) {
    this.group = group;
    this.value = value;
  }

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

  public BigInteger multiply(BigInteger val) {
    return value.multiply(val);
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

  public BigInteger modPow(BigInteger exponent, BigInteger m) {
    return value.modPow(exponent, m);
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

  public boolean equals(Object x) {
    return value.equals(x);
  }

  public BigInteger min(BigInteger val) {
    return value.min(val);
  }

  public BigInteger max(BigInteger val) {
    return value.max(val);
  }

  public int hashCode() {
    return value.hashCode();
  }

  public String toString(int radix) {
    return value.toString(radix);
  }

  public String toString() {
    return value.toString();
  }

  public byte[] toByteArray() {
    return value.toByteArray();
  }

  public Group getGroup() {
    return group;
  }
}
