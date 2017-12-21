package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/**
 * Quadratic Group
 */
public class QRGroup implements Group {

    private final BigInteger modulus;
    private final BigInteger pPrime;
    private final BigInteger qPrime;
    private final BigInteger order;

    private BigInteger generator;


    public QRGroup(BigInteger pPrime, BigInteger qPrime) {

        this.modulus = pPrime.multiply(qPrime);
        this.pPrime = pPrime;
        this.qPrime = qPrime;
        this.order = computeGroupOrder(pPrime, qPrime);

    }

    private BigInteger computeGroupOrder(BigInteger pPrime, BigInteger qPrime) {
        // TODO check if calculation is correct for QRGroup when the factorization is known
        return pPrime.subtract(BigInteger.ONE).multiply(qPrime.subtract(BigInteger.ONE));
    }


    @Override
    public BigInteger getOrder() {
        return this.order;
    }

    public BigInteger getModulus() {
        return this.modulus;
    }

    @Override
    public BigInteger getGenerator() {
        return this.generator;
    }

    @Override
    public QRElement createGenerator() {
        return new QRElement(this, CryptoUtilsFacade.computeQRNGenerator(this.modulus));
    }

    /**
     * Algorithm <tt>alg:element_of_QR_N</tt> - topocert-doc
     * Determines if an integer  alpha is an element of QRN
     * 
     * @param alpha candidate integer alpha,
     * @return  true if alpha in QRN, false if alpha not in QRN
     * Dependencies: jacobiSymbol()
     */
    @Override
    public boolean isElement(BigInteger alpha) {
        // TODO check if it is correct
        return alpha.compareTo(BigInteger.ZERO) > 0 && alpha.compareTo(modulus.subtract(BigInteger.ONE).divide(NumberConstants.TWO.getValue())) <= 0
                && JacobiSymbol.computeJacobiSymbol(alpha, pPrime) == 1 && JacobiSymbol.computeJacobiSymbol(alpha, qPrime) == 1;

    }
}
