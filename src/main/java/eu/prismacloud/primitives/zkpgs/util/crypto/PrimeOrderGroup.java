package eu.prismacloud.primitives.zkpgs.util.crypto;

import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;

import java.math.BigInteger;
import java.util.logging.Logger;

/**
 * Constructs a subgroup of prime order q of \( Z^{*}_{p} \).
 */
public class PrimeOrderGroup extends Group {
	private static Logger log = GSLoggerConfiguration.getGSlog();
	private final BigInteger pPrime;
	private final BigInteger qPrime;
	private GroupElement generator;

	public PrimeOrderGroup(final BigInteger pPrime, final BigInteger qPrime) {
		Assert.notNull(pPrime, "pPrime must not be null");
		Assert.notNull(qPrime, "qPrime must not be null");
//		log.info("p: " + pPrime);
//		log.info("p bitlength : " + pPrime.bitLength());
//
//		log.info("q: " + qPrime);
		//		log.info("q bitlength : " + qPrime.bitLength());

		this.pPrime = pPrime;
		this.qPrime = qPrime;
		validateGroup(pPrime, qPrime);
	}

	private void validateGroup(final BigInteger p, final BigInteger q) {
		if (p.subtract(BigInteger.ONE).remainder(q).signum() != 0) {
			throw new IllegalStateException("q must divide p - 1");
		}

		if (!CryptoUtilsFacade.isPrime(p)) {
			throw new IllegalStateException("p is not prime");
		}

		if (!CryptoUtilsFacade.isPrime(q)) {
			throw new IllegalStateException("q is not prime");
		}

	}

	@Override
	public BigInteger getOrder() throws UnsupportedOperationException {
		return this.qPrime;
	}

	@Override
	public GroupElement getGenerator() {
		return this.generator;
	}

	@Override
	public BigInteger getModulus() {
		return this.pPrime;
	}


	/**
	 * Indicates whether the input value is an element of the prime order group.
	 * Checks that  \( value > 1 \),   \( value < p \) and   value^{q} \bmod p == 1.
	 *
	 * @param value the BigInteger to check if it belongs to the group.
	 * @return <code>true</code> if the value parameter belongs to the group; <code>false</code> otherwise.
	 */
	@Override
	public boolean isElement(final BigInteger value) throws UnsupportedOperationException {
		return ((value.compareTo(BigInteger.ONE) > 0) && (value.compareTo(this.pPrime) < 0) && (value.modPow(this.qPrime, this.pPrime).equals(BigInteger.ONE)));
	}

	@Override
	public GroupElement createGenerator() {
		BigInteger g;
		do {
			BigInteger h = CryptoUtilsFacade.createElementOfZNS(this.pPrime);
			BigInteger exp = this.pPrime.subtract(BigInteger.ONE).divide(this.qPrime);
			g = h.modPow(exp, this.pPrime);
		} while (!isElement(g));

		this.generator = new PrimeOrderGroupElement(this, g);
		return generator;
	}

	@Override
	public GroupElement createRandomElement() {
		BigInteger h;
		BigInteger el;

		do {
			h = CryptoUtilsFacade.createElementOfZNS(this.pPrime);
			el = h.modPow(NumberConstants.TWO.getValue(), this.pPrime);
		}
		while (!this.isElement(h));
		return new PrimeOrderGroupElement(this, el);
	}


	@Override
	public GroupElement createElement(final BigInteger value) throws IllegalArgumentException, UnsupportedOperationException {
		return null;
	}

	@Override
	public boolean isKnownOrder() {
		return true;
	}

	@Override
	public GroupElement getOne() {
		return new PrimeOrderGroupElement(this, BigInteger.ONE);
	}

	@Override
	public Group publicClone() {
		return null;
	}

	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder("eu.prismacloud.primitives.zkpgs.util.crypto.PrimeOrderGroup{");
		sb.append("pPrime=").append(pPrime);
		sb.append(", qPrime=").append(qPrime);
		sb.append(", generator=").append(generator);
		sb.append(", order=").append(getOrder());
		sb.append(", modulus=").append(getModulus());
		sb.append(", createGenerator=").append(createGenerator());
		sb.append(", createRandomElement=").append(createRandomElement());
		sb.append(", knownOrder=").append(isKnownOrder());
		sb.append(", one=").append(getOne());
		sb.append(", publicClone=").append(publicClone());
		sb.append('}');
		return sb.toString();
	}
}