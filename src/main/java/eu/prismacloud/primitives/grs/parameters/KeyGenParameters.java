package eu.prismacloud.primitives.grs.parameters;

/**
 * Enum for key generation parameters displayed in table:params of the topocert documentation. 
 */
public enum KeyGenParameters {
    /** Bit length of the special RSA modulus */
    l_n(2048),

    /** Bit length of the commitment group */
    l_gamma(1632),

    /** Bit length of the prime order of the subgroup of Γ */
    l_rho(256),

    /** Maximal bit length of messages encoding vertices and 256 edges */
    l_m(256),

    /** Number of reserved messages */
    l_res(1),

    /** Bit length of the certificate component e */
    l_e(597),

    /** Bit length of the interval the e values are taken from */
    l_prime_e(120),

    /** Bit length of the certificate component v */
    l_v(2724),

    /** Security parameter for statistical zero-knowledge */
    l_0(80),

    /** Bit length of the cryptographic hash function used for 256 the Fiat-Shamir Heuristic */
    l_H(256),

    /** Security parameter for the security proof of the CL-scheme */
    l_r(80),

    /** The prime number generation to have an error probability to return a composite of \( 1 - \frac{1}{2}^{l_{pt}} \) */
    l_pt(80);
    

    private final int paramValue;

    KeyGenParameters(int paramValue) {
        this.paramValue = paramValue;
    }

    public int getValue() {
        return this.paramValue;
    }
}
