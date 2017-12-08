package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Constants for BigIntegers
 */
public enum NumberConstants {

    TWO(BigInteger.valueOf(2));


    private final BigInteger bigConstant;

    NumberConstants(BigInteger bigInteger) {
        this.bigConstant = bigInteger;
    }

    public BigInteger getValue() {
        return bigConstant;
    }
}
