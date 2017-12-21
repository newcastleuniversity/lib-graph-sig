package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * element of Quadratic Residue
 */
public class QRElement {
    private QRGroup group;


    private final BigInteger representation;

    public QRElement(BigInteger representation) {
        this.representation = representation;
    }

    public QRElement(final QRGroup group, final BigInteger representation) {

        this.group = group;
        this.representation = representation;
    }

    public BigInteger getRepresentation() {
        return representation;
    }

    public BigInteger nextProbablePrime() {
        return representation.nextProbablePrime();
    }

    public BigInteger add(BigInteger val) {
        return representation.add(val);
    }

    public BigInteger subtract(BigInteger val) {
        return representation.subtract(val);
    }

    public BigInteger multiply(BigInteger val) {
        return representation.multiply(val);
    }

    public BigInteger divide(BigInteger val) {
        return representation.divide(val);
    }

    public BigInteger[] divideAndRemainder(BigInteger val) {
        return representation.divideAndRemainder(val);
    }

    public BigInteger remainder(BigInteger val) {
        return representation.remainder(val);
    }

    public BigInteger gcd(BigInteger val) {
        return representation.gcd(val);
    }

    public BigInteger abs() {
        return representation.abs();
    }

    public BigInteger negate() {
        return representation.negate();
    }

    public int signum() {
        return representation.signum();
    }

    public BigInteger mod(BigInteger m) {
        return representation.mod(m);
    }

    public BigInteger modPow(BigInteger exponent, BigInteger m) {
        return representation.modPow(exponent, m);
    }

    public BigInteger modInverse(BigInteger m) {
        return representation.modInverse(m);
    }

    public int getLowestSetBit() {
        return representation.getLowestSetBit();
    }

    public int bitLength() {
        return representation.bitLength();
    }

    public int bitCount() {
        return representation.bitCount();
    }

    public boolean isProbablePrime(int certainty) {
        return representation.isProbablePrime(certainty);
    }

    public int compareTo(BigInteger val) {
        return representation.compareTo(val);
    }

    public boolean equals(Object x) {
        return representation.equals(x);
    }

    public BigInteger min(BigInteger val) {
        return representation.min(val);
    }

    public BigInteger max(BigInteger val) {
        return representation.max(val);
    }

    public int hashCode() {
        return representation.hashCode();
    }

    public String toString(int radix) {
        return representation.toString(radix);
    }

    public String toString() {
        return representation.toString();
    }

    public byte[] toByteArray() {
        return representation.toByteArray();
    }

    public QRGroup getGroup() {
        return group;
    }
}
