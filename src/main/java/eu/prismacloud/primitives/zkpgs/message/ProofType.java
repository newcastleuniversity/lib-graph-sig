package eu.prismacloud.primitives.zkpgs.message;

import java.io.Serializable;

/**
 * Current supported proof types
 */
public enum ProofType implements Serializable {
    GEOLOCATION_SEPARATION,
    NONE
}
