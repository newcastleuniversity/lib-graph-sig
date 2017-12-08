package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * element of Quadratic Residue
 */
public class QRElement {
	public QRElement(BigInteger representation) {
		this._representation = representation;
	}
	
	
	private final BigInteger _representation;

	public BigInteger nextProbablePrime() {
		return _representation.nextProbablePrime();
	}

	public BigInteger add(BigInteger val) {
		return _representation.add(val);
	}

	public BigInteger subtract(BigInteger val) {
		return _representation.subtract(val);
	}

	public BigInteger multiply(BigInteger val) {
		return _representation.multiply(val);
	}

	public BigInteger divide(BigInteger val) {
		return _representation.divide(val);
	}

	public BigInteger[] divideAndRemainder(BigInteger val) {
		return _representation.divideAndRemainder(val);
	}

	public BigInteger remainder(BigInteger val) {
		return _representation.remainder(val);
	}

	public BigInteger gcd(BigInteger val) {
		return _representation.gcd(val);
	}

	public BigInteger abs() {
		return _representation.abs();
	}

	public BigInteger negate() {
		return _representation.negate();
	}

	public int signum() {
		return _representation.signum();
	}

	public BigInteger mod(BigInteger m) {
		return _representation.mod(m);
	}

	public BigInteger modPow(BigInteger exponent, BigInteger m) {
		return _representation.modPow(exponent, m);
	}

	public BigInteger modInverse(BigInteger m) {
		return _representation.modInverse(m);
	}

	public int getLowestSetBit() {
		return _representation.getLowestSetBit();
	}

	public int bitLength() {
		return _representation.bitLength();
	}

	public int bitCount() {
		return _representation.bitCount();
	}

	public boolean isProbablePrime(int certainty) {
		return _representation.isProbablePrime(certainty);
	}

	public int compareTo(BigInteger val) {
		return _representation.compareTo(val);
	}

	public boolean equals(Object x) {
		return _representation.equals(x);
	}

	public BigInteger min(BigInteger val) {
		return _representation.min(val);
	}

	public BigInteger max(BigInteger val) {
		return _representation.max(val);
	}

	public int hashCode() {
		return _representation.hashCode();
	}

	public String toString(int radix) {
		return _representation.toString(radix);
	}

	public String toString() {
		return _representation.toString();
	}

	public byte[] toByteArray() {
		return _representation.toByteArray();
	}
	
}
