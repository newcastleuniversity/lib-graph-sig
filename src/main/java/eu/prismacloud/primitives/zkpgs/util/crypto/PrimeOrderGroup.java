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

	/**
	 * Instantiates a new Prime order group.
	 *
	 * @param pPrime the p prime
	 * @param qPrime the q prime
	 */
	public PrimeOrderGroup(final BigInteger pPrime, final BigInteger qPrime) {
		Assert.notNull(pPrime, "pPrime must not be null");
		Assert.notNull(qPrime, "qPrime must not be null");

		this.pPrime = pPrime;
		this.qPrime = qPrime;
		validateGroup(pPrime, qPrime);
	}

	/**
	 * Instantiates a new Prime order group.
	 *
	 * @param pPrime    the p prime
	 * @param qPrime    the q prime
	 * @param generator the generator
	 */
	public PrimeOrderGroup(final BigInteger pPrime, final BigInteger qPrime, final BigInteger generator) {
		Assert.notNull(pPrime, "pPrime must not be null");
		Assert.notNull(qPrime, "qPrime must not be null");
		Assert.notNull(generator, "generator must not be null");

		validateGroup(pPrime, qPrime);
        this.pPrime = pPrime;
		this.qPrime = qPrime;

		if (!isElement(generator)) throw new IllegalArgumentException("generator is not member of group");
		this.generator = new PrimeOrderGroupElement(this, generator);
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
	 * Checks that {@literal \( value > 1 \)}, {@literal \( value < p \)}  and  \(value^{q} \bmod p == 1 \).
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
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		PrimeOrderGroup that = (PrimeOrderGroup) o;

		if (!pPrime.equals(that.pPrime)) return false;
		if (!qPrime.equals(that.qPrime)) return false;
		return generator.equals(that.generator);
	}

	@Override
	public int hashCode() {
		int result = pPrime != null ? pPrime.hashCode() : 0;
		result = 31 * result + (qPrime != null ? qPrime.hashCode() : 0);
		result = 31 * result + (generator != null ? generator.hashCode() : 0);
		return result;
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
