package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 *
 * Class that represents an element in the Quadratic Residues group
 * that we the modulus factorization is known.
 *
 */
public class QRElementPQ extends QRElement{
    private QRGroupPQ qrGroupPQ;
    private BigInteger number;
    private BigInteger order;

    public QRElementPQ(BigInteger value) {
        super(value);
    }

    public QRElementPQ(QRGroupPQ qrGroupPQ, BigInteger number) {
        super(qrGroupPQ, number);

        this.qrGroupPQ = qrGroupPQ;
        this.number = number;
    }

    public QRElementPQ(QRGroupPQ qrGroupPQ, BigInteger number, BigInteger pPrime, BigInteger qPrime) {
        super(qrGroupPQ, number);
        this.qrGroupPQ = qrGroupPQ;
        this.number = number;
        this.order = pPrime.multiply(qPrime);
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
