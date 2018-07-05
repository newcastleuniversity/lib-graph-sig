package eu.prismacloud.primitives.zkpgs.util.crypto;

import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/** Quadratic Residues Group when the modulus factorization is known. */
public final class QRGroupPQ extends QRGroup {

	private final BigInteger pPrime;
	private final BigInteger qPrime;
	private final BigInteger p;
	private final BigInteger q;
	private final BigInteger order;
	private final BigInteger oneP;
	private final BigInteger oneQ;
	
	
	/**
	 * Instantiates a new QR group where we know the modulus factorization.
	 *
	 * @param pPrime the p prime
	 * @param qPrime the q prime
	 * @pre pPrime != null && qPrime != null
	 * @post
	 */
	public QRGroupPQ(final BigInteger pPrime, final BigInteger qPrime) {
		super(
				((NumberConstants.TWO.getValue().multiply(pPrime)).add(BigInteger.ONE)).multiply(
						((NumberConstants.TWO.getValue().multiply(qPrime)).add(BigInteger.ONE)))
				);
		
		Assert.notNull(pPrime, "pPrime must not be null");
		Assert.notNull(qPrime, "qPrime must not be null");
		this.pPrime = pPrime;
		this.qPrime = qPrime;
		this.p = (NumberConstants.TWO.getValue().multiply(pPrime)).add(BigInteger.ONE);
		this.q = (NumberConstants.TWO.getValue().multiply(qPrime)).add(BigInteger.ONE);
		this.order = this.getOrder();
		QRGroupPQ.computeEEA(pPrime, qPrime);
		this.oneP = CRT.compute1p(EEAlgorithm.getT(), pPrime, qPrime); // TODO doublecheck. This should be mod p, right?
		this.oneQ = CRT.compute1q(EEAlgorithm.getS(), pPrime, qPrime);
	}

	private static void computeEEA(final BigInteger p, final BigInteger q) {
		EEAlgorithm.computeEEAlgorithm(p, q);
	}

	@Override
	public BigInteger getOrder() {
		// (p-1)(q-1)/4 = pPrime * qPrime
		return this.pPrime.multiply(this.qPrime);
	}

//	@Override
//	public QRElement createRandomElement() {
//		return new QRElementPQ(this, CryptoUtilsFacade.computeQRNElement(this.modulus).getValue(), pPrime, qPrime);
//	}

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
	 * element of QRN if the factorization of a Special RSA modulus is known \(N = pq\) then \((a | p)
	 * = 1 \land (a | q) = 1\)
	 *
	 * @param alpha candidate integer alpha,
	 * @return true if alpha in QRN, false if alpha not in QRN
	 */
	@Override
	public boolean isElement(final BigInteger alpha) {
		return (computeLegendreP(alpha).equals(BigInteger.ONE) && 
				computeLegendreQ(alpha).equals(BigInteger.ONE));
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
		if (!S.equals(BigInteger.ONE.mod(this.getModulus()))) {
			if (!S.modPow(pPrime, this.getModulus()).equals(BigInteger.ONE.mod(this.getModulus())))
				return !S.modPow(qPrime, this.getModulus()).equals(BigInteger.ONE.mod(this.getModulus()));
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
	 * Computes the Legendre symbol of a BigInteger value with respect to the
	 * prime factor p of this QRGroupPQ.
	 *  
	 * @param value BigInteger
	 * @return -1 if value is not a Quadratic Residue modulo p, 
	 *               0 if p divides the value, and 
	 *               +1 if value is a Quadratic Residue modulo p.
	 */
	public BigInteger computeLegendreP(BigInteger value) {
		return value.modPow(this.pPrime, this.p);
	}
	
	/**
	 * Computes the Legendre symbol of a BigInteger value with respect to the
	 * prime factor q of this QRGroupPQ.
	 *  
	 * @param value BigInteger
	 * @return -1 if value is not a Quadratic Residue modulo q, 
	 *               0 if q divides the value, and 
	 *               +1 if value is a Quadratic Residue modulo q.
	 */
	public BigInteger computeLegendreQ(BigInteger value) {
		return value.modPow(this.qPrime, this.q);
	}

	/**
	 * Creates the QRGroupN that corresponds to this group, however, without any secret information.
	 * 
	 * @return QRGroupN corresponding to this group
	 */
	public QRGroupN getPublicQRGroup() {
		return new QRGroupN(this.getModulus());
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
		return (QRElementPQ) super.getOne();
	}
}
