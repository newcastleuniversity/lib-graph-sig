package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Class that represents an element in Quadratic Residues group
 * without knowing the factorization of modulus N.
 */
public class QRElementN extends QRElement {
    private QRGroupN qrGroup;
    private BigInteger number;

    public QRElementN(QRGroupN qrGroup, BigInteger number) {
        
        super(qrGroup, number);
        this.qrGroup = qrGroup;
        this.number = number;

    }

    public QRElementN(BigInteger value) {
        super(value);
    }

    public QRElementN(Group group, BigInteger value) {
        super(group, value);
    }

    @Override
    public Group getGroup() {
        return qrGroup;
    }

    @Override
    public BigInteger getValue() {
        return number;
    }
}
