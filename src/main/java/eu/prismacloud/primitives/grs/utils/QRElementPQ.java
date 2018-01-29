package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Class that represents an element in the Quadratic Residues group
 * that we the modulus factorization is known.
 */
public class QRElementPQ extends QRElement {
    private QRGroupPQ qrGroupPQ;
    private BigInteger number;
    private BigInteger order;
    private BigInteger xp;
    private BigInteger xq;

    public QRElementPQ(final BigInteger value) {
        super(value);
    }

    public QRElementPQ(final QRGroupPQ qrGroupPQ, final BigInteger number) {
        super(qrGroupPQ, number);

        this.qrGroupPQ = qrGroupPQ;
        this.number = number;
    }

    public QRElementPQ(final QRGroupPQ qrGroupPQ, final BigInteger number, final BigInteger pPrime, final BigInteger qPrime) {
        super(qrGroupPQ, number);
        this.qrGroupPQ = qrGroupPQ;
        this.number = number;
        this.order = pPrime.multiply(qPrime);
    }

    public BigInteger getXp() {
        return xp;
    }

    public BigInteger getXq() {
        return xq;
    }

    /**
     * CRT representation
     *
     * @param xp
     * @param xq
     */
    public void setPQRepresentation(BigInteger xp, BigInteger xq) {

        this.xp = xp;
        this.xq = xq;
    }


    @Override
    public Group getGroup() {
        return this.qrGroupPQ;
    }

    @Override
    public BigInteger getValue() {
        return this.number;
    }

    public BigInteger getOrder() {
        return this.order;
    }
}
