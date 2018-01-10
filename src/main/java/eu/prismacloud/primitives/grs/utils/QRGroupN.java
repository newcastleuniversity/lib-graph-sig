package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Quadratic Residue Group where we don't know the modulus factorization in \(Z^*_p \)
 */
public final class QRGroupN extends Group {

    private final BigInteger modulus;


    public QRGroupN(final BigInteger modulus) {
        this.modulus = modulus;
    }

    @Override
    public BigInteger getOrder() {
        // (modulus - 1) / 2
        return modulus.subtract(BigInteger.ONE).divide(NumberConstants.TWO.getValue());
    }

    @Override
    public GroupElement getGenerator() {
        return null;
    }

    public QRElementN createGenerator() {
        return new QRElementN(this, CryptoUtilsFacade.computeQRNGenerator(this.modulus));
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
