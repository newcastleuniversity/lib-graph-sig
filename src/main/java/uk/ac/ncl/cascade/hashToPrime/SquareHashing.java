package uk.ac.ncl.cascade.hashToPrime;

import uk.ac.ncl.cascade.zkpgs.util.Assert;

import java.math.BigInteger;

/**
 * Implements the square hash function that is strongly universal (SQHU) based on (Etzel et a.1999).
 * Etzel, M., Patel, S., and Ramzan, Z. (1999). Square hash:
 * Fast message authentication via optimized universal hash functions.
 */
public class SquareHashing {
	private final BigInteger p;
	private final BigInteger z;
	private final BigInteger b;
	private final int TWO = 2;

	/**
	 * Constructs a new instance of the square hash function.
	 * Note that parameter p is a prime number. Parameters z and b
	 * are defined such that \( x,b \in Z_{p} \).
	 *
	 * @param p the big integer prime p parameter for the square hash
	 * @param z the big integer z parameter for the square hash
	 * @param b the big integer b parameter for the square hash
	 */
	public SquareHashing(final BigInteger p, final BigInteger z, final BigInteger b) {
		Assert.notNull(p, "p parameter for the square hash must not be null");
		Assert.notNull(z, "z parameter for the square hash must not be null");
		Assert.notNull(b, "b parameter for the square hash must not be null");

		this.p = p;
		this.z = z;
		this.b = b;
	}

	/**
	 * Computes the square hash of the big integer input
	 * \( (x + z)^{2} + b \mod p \)
	 *
	 * @param x big integer number for the square hash
	 * @return a big integer representing the result of the square hash computation
	 */
	public BigInteger hash(BigInteger x) {
		Assert.notNull(x, "input to computing the square hash must not be null");
		return x.add(this.z).pow(TWO).add(this.b).mod(this.p);
	}
}
