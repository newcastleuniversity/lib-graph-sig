package eu.prismacloud.primitives.grs;

import java.math.BigInteger;


public class GroupSetup {
    /**
     * Commitment group order.
     */
    private final BigInteger capGamma;
    /**
     * Order of the subgroup of the commitment group.
     */
    private final BigInteger rho;
    /**
     * Generator.
     */
    private final BigInteger g;
    /**
     * Generator.
     */
    private final BigInteger h;

    public GroupSetup(BigInteger capGamma, BigInteger rho, BigInteger g, BigInteger h) {
        this.capGamma = capGamma;
        this.rho = rho;
        this.g = g;
        this.h = h;
    }

    public static GroupSetup generateGroupSetup() {
        /* TODO perform computations */
        return null;
    }
}
