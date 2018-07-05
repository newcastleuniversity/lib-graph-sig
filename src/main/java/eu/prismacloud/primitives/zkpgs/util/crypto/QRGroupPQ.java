package eu.prismacloud.primitives.zkpgs.util.crypto;

import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/** Quadratic Residues Group when the modulus factorization is known. */
public final class QRGroupPQ extends QRGroup {

	private final BigInteger modulus;
	private final BigInteger pPrime;
	private final BigInteger qPrime;
	private final BigInteger p;
	private final BigInteger q;
	private final BigInteger order;
	private final BigInteger oneP;
	private final BigInteger oneQ;
	private QRElementPQ generator;

	private final QRElementPQ one;
	
	/**
	 * Instantiates a new QR group where we know the modulus factorization.
	 *
	 * @param pPrime the p prime
	 * @param qPrime the q prime
	 * @pre pPrime != null && qPrime != null
	 * @post
	 */
	public QRGroupPQ(final BigInteger pPrime, final BigInteger qPrime) {
		super();
		
		Assert.notNull(pPrime, "pPrime must not be null");
		Assert.notNull(qPrime, "qPrime must not be null");
		this.modulus = pPrime.multiply(qPrime);
		this.pPrime = pPrime;
		this.qPrime = qPrime;
		this.p = (NumberConstants.TWO.getValue().multiply(pPrime)).add(BigInteger.ONE);
		this.q = (NumberConstants.TWO.getValue().multiply(qPrime)).add(BigInteger.ONE);
		this.order = this.getOrder();
		QRGroupPQ.computeEEA(pPrime, qPrime);
		this.oneP = CRT.compute1p(EEAlgorithm.getT(), pPrime, qPrime); // TODO doublecheck. This should be mod p, right?
		this.oneQ = CRT.compute1q(EEAlgorithm.getS(), pPrime, qPrime);
		this.one = new QRElementPQ(this, BigInteger.ONE);
	}

	private static void computeEEA(final BigInteger p, final BigInteger q) {
		EEAlgorithm.computeEEAlgorithm(p, q);
	}

	@Override
	public BigInteger getOrder() {
		// (p-1)(q-1)/4 = pPrime * qPrime
		return this.pPrime.multiply(this.qPrime);
	}

	@Override
	public BigInteger getModulus() {
		return this.modulus;
	}

	@Override
	public GroupElement getGenerator() {
		return this.generator;
	}

	/**
	 * Create generator group element for QRN when the modulus factorization is known.
	 *
	 * @return the group element
	 */
	@Override
	public QRElement createGenerator() {
		return this.generator =
				new QRElementPQ(this, CryptoUtilsFacade.computeQRNGenerator(this.modulus).getValue(), pPrime, qPrime);
	}

	@Override
	public QRElement createRandomElement() {
		return new QRElementPQ(this, CryptoUtilsFacade.computeQRNElement(this.modulus).getValue(), pPrime, qPrime);
	}

	//  @Override
	//  public GroupElement createElement(final GroupElement s) {
	//    QRElementPQ qrElementPQ;
	//    BigInteger upperBound = this.pPrime.multiply(this.qPrime).subtract(BigInteger.ONE);
	//
	//    do {
	//      BigInteger exponent =
	//          CryptoUtilsFacade.computeRandomNumber(NumberConstants.TWO.getValue(), upperBound);
	//      qrElementPQ = new QRElementPQ(this, s.modPow(exponent, this.modulus).getValue());
	//
	//    } while (!isElement(qrElementPQ.getValue()));
	//
	//    /** TODO remove groupelement list */
	//    /** TODO  add invariant for qrelement */
	//    this.groupElements.add(qrElementPQ);
	//
	//    return qrElementPQ;
	//  }

	/**
	 * Algorithm <tt>alg:element_of_QR_N</tt> - topocert-doc Determines if an integer alpha is an
	 * element of QRN If the factorization of a Special RSA modulus is known \(N = pq\) then \((a | p)
	 * = 1 \land (a | q) = 1\)
	 *
	 * @param alpha candidate integer alpha,
	 * @return true if alpha in QRN, false if alpha not in QRN Dependencies: jacobiSymbol()
	 */
	@Override
	public boolean isElement(final BigInteger alpha) {
		// TODO check if computations are correct
		return CryptoUtilsFacade.isElementOfQR(alpha, pPrime)
				&& CryptoUtilsFacade.isElementOfQR(alpha, qPrime);
	}

	/**
	 * Algorithm <tt>alg:verifySGeneratorOfQRN</tt> - topocert-doc Verify s generator boolean.
	 *
	 * @param S the generator S
	 * @param pPrime the p prime
	 * @param qPrime the q prime
	 * @return true if S is a generator of QRN or false if it is not
	 */
	public boolean verifySGenerator(
			final BigInteger S, final BigInteger pPrime, final BigInteger qPrime) {
		if (!S.equals(BigInteger.ONE.mod(modulus))) {
			if (!S.modPow(pPrime, modulus).equals(BigInteger.ONE.mod(modulus)))
				return !S.modPow(qPrime, modulus).equals(BigInteger.ONE.mod(modulus));
		} else return false;

		return false;
	}

	/**
	 * Algorithm <tt>alg:verifySGeneratorOfQRN_alt</tt> - topocert-doc Verify S generator (alternative
	 * implementation).
	 *
	 * @param S the generator
	 * @param modN the modulus
	 * @return true if S is a generator of QRN or false if it is not
	 */
	public boolean verifySGenerator(final BigInteger S, final BigInteger modN) {
		return S.subtract(BigInteger.ONE).gcd(modN).equals(BigInteger.ONE);
	}

	/**
	 * Gets one with respect to modulus p.
	 *
	 * @return the one p
	 */
	public BigInteger getOneP() {
		return oneP;
	}

	/**
	 * Gets one with respect to modulus q.
	 *
	 * @return the one q
	 */
	public BigInteger getOneQ() {
		return oneQ;
	}
	

	/**
	 * Returns the factor p.
	 *
	 * @return p
	 */
	public BigInteger getP() {
		return this.p;
	}
	

	/**
	 * Returns the factor q.
	 *
	 * @return g
	 */
	public BigInteger getQ() {
		return this.q;
	}

	/**
	 * Creates the QRGroupN that corresponds to this group, however, without any secret information.
	 * 
	 * @return QRGroupN corresponding to this group
	 */
	public QRGroupN getPublicQRGroup() {
		return new QRGroupN(this.modulus);
	}

	@Override
	public GroupElement createElement(BigInteger value) {
		// TODO Auto-generated method stub
		// Check whether this BigInteger value is a valid element:
		// Compute the Legendre symbol wrt. p and q.
		return null;
	}

	@Override
	public boolean isKnownOrder() {
		return true;
	}
	
	@Override
	public QRElementPQ getOne() {
		return this.one;
	}
}
