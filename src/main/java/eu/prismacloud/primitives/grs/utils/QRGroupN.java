package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Quadratic Residue Group where we don't know the modulus factorization in \(Z^*_p \)
 */
public final class QRGroupN extends Group {

    private final BigInteger modulus;
    private QRElementN generator;


    public QRGroupN(final BigInteger modulus) {
        this.modulus = modulus;
    }

    @Override
    public BigInteger getOrder() {
        throw new RuntimeException("Order must not be known");
    }

    @Override
    public GroupElement getGenerator() {
        return this.generator;
    }

    public QRElementN createGenerator() {
        return this.generator = new QRElementN(this, CryptoUtilsFacade.computeQRNGenerator(this.modulus));
    }

    @Override
    public BigInteger getModulus() {
        return this.modulus;
    }

    @Override
    public boolean isElement(BigInteger value) {
        return false;
    }

    /**
     * Check if an element \( x \in Z^*_p \) is a quadratic residue.
     *
     * @param x the number to check for quadratic residuosity
     * @return the boolean
     */
    public boolean isQR(BigInteger x) {

        return JacobiSymbol.computeJacobiSymbol(x, this.modulus) == 1;
    }
}
