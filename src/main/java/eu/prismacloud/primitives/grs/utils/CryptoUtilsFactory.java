package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Provide a factory for different low-level implementations of number theoretic computations
 */
public class CryptoUtilsFactory {

    private static IdemixUtils idemixUtil;
    private static GSUtils gsUtil;

    CryptoUtilsFactory() {
    }

    /**
     * Create an instance of IDEMIX or GS utility classes for Number Theoretic computations
     *
     * @param name the name of the utility class
     * @return instance of factory class
     * @throws IllegalArgumentException if name is empty or null
     */
    public static INumberUtils getInstance(String name) throws IllegalArgumentException {

        if ((name == null) || (name.length() == 0))
            throw new IllegalArgumentException("Missing number theoretic utility class");

        switch (name) {
            case "IDEMIX":

                // return new IdemixUtils();
                return idemixUtil = (idemixUtil == null) ? new IdemixUtils() : idemixUtil;

            case "GS":
                //return new GSUtils();
                return gsUtil = (gsUtil == null) ? new GSUtils() : gsUtil;
            default:

                return null;
        }
    }


}
