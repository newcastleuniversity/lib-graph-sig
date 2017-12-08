package eu.prismacloud.primitives.grs.parameters;

/**
 * Created by Ioannis Sfyrakis on 23/11/2017
 */
public enum GraphEncodingParameters {
    /** Maximal number of vertices to be encoded */
    l_V(1000),

    /** Reserved bit length for vertex encoding (bit length of
    the largest encodable prime representative) */
    l_prime_V(120),

    /** Maximal number of edges to be encoded */
    l_E(50000),

    /** Maximal number of labels to be encoded */
    l_L(256),
    
    /** Reserved bit length for label encoding */
    l_prime_L(16);


    private final int paramValue;

    GraphEncodingParameters(int paramValue) {
        this.paramValue = paramValue;
    }

    public int getValue() {
        return paramValue;
    }
}
