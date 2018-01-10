package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Quadratic Residues Group when the modulus factorization is known
 */
public final class QRGroupPQ extends Group {

    private final BigInteger modulus;
    private final BigInteger pPrime;
    private final BigInteger qPrime;
    private final BigInteger order;
    private GroupElement generator;// = BigInteger.ONE;

    /**
     * Instantiates a new QR group where we know the modulus factorization.
     *
     * @param pPrime the p prime
     * @param qPrime the q prime
     */
    public QRGroupPQ(final BigInteger pPrime, final BigInteger qPrime) {

        this.modulus = pPrime.multiply(qPrime);
        this.pPrime = pPrime;
        this.qPrime = qPrime;
        this.order = getOrder();

    }


    @Override
    public BigInteger getOrder() {
        // (p-1)(q-1)/4
        return this.pPrime.subtract(BigInteger.ONE).multiply(this.qPrime.subtract(BigInteger.ONE)).divide(NumberConstants.FOUR.getValue());
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
     * Create generator group element for QRN.
     * when the modulus factorization is known.
     *
     * @return the group element
     */
    public GroupElement createGenerator() {
        return this.generator = new QRElementPQ(this, CryptoUtilsFacade.computeQRNGenerator(this.modulus), pPrime, qPrime);
    }

    /**
     * Algorithm <tt>alg:element_of_QR_N</tt> - topocert-doc
     * Determines if an integer  alpha is an element of QRN
     * If the factorization of a Special RSA modulus is known
     * \(N = pq\) then \((a | p) = 1 \land (a | q) = 1\)
     *
     * @param alpha candidate integer alpha,
     * @return true if alpha in QRN, false if alpha not in QRN
     * Dependencies: jacobiSymbol()
     */
    @Override
    public boolean isElement(BigInteger alpha) {
        // TODO check if computations are correct
        return CryptoUtilsFacade.isElementOfQR(alpha, pPrime) && CryptoUtilsFacade.isElementOfQR(alpha, qPrime);

    }

    /**
     * Algorithm <tt>alg:verifySGeneratorOfQRN</tt> - topocert-doc
     * Verify s generator boolean.
     *
     * @param S      the generator S
     * @param pPrime the p prime
     * @param qPrime the q prime
     * @return true if S is a generator of QRN or false if it is not
     */
    public boolean verifySGenerator(BigInteger S, BigInteger pPrime, BigInteger qPrime) {
        if (!S.equals(BigInteger.ONE.mod(modulus))) {
            if (!S.modPow(pPrime, modulus).equals(BigInteger.ONE.mod(modulus)))
                return !S.modPow(qPrime, modulus).equals(BigInteger.ONE.mod(modulus));
        } else return false;

        return false;

    }
}
