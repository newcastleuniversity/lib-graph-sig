package uk.ac.ncl.cascade.hashToPrime;

import java.math.BigInteger;

/**
 * Creates a family of square hash functions that is strongly universal (SQHU) based on (Etzel et a.1999).
 * Etzel, M., Patel, S., and Ramzan, Z. (1999). Square hash:
 * Fast message authentication via optimized universal
 * hash functions.
 */
public class SquareHashing {
	private final BigInteger modulus;
	private final BigInteger z;
	private final BigInteger b;

	private final int TWO = 2;


	public SquareHashing(final BigInteger modulus, final BigInteger z, final BigInteger b) {
		this.modulus = modulus;
		this.z = z;
		this.b = b;
	}


	/**
	 * Computes square hash.
	 *
	 * @param x number for the square hash
	 * @return
	 */
	public BigInteger hash(BigInteger x) {
		return x.add(z).pow(TWO).add(b).mod(modulus);
	}
}
