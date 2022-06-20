package uk.ac.ncl.cascade.zkpgs.message;

import java.io.Serializable;

/**
 * Current supported proof types
 */
public enum ProofType implements Serializable {
    GEOLOCATION_SEPARATION,
    VC_CRED,
    NONE
}
