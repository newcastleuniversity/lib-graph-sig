package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Constants for BigIntegers
 */
public enum NumberConstants {

    TWO(BigInteger.valueOf(2)),
    THREE(BigInteger.valueOf(3)),
    FOUR(BigInteger.valueOf(4)),
    SEVEN(BigInteger.valueOf(7)),
    EIGHT(BigInteger.valueOf(8)),
    FIVE(BigInteger.valueOf(5));

    private final BigInteger bigConstant;

    NumberConstants(BigInteger bigInteger) {
        this.bigConstant = bigInteger;
    }

    public BigInteger getValue() {
        return bigConstant;
    }
}
