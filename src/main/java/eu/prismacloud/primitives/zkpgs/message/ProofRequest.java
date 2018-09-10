package eu.prismacloud.primitives.zkpgs.message;

import java.io.Serializable;
import java.util.Vector;

/**
 * The ProofRequest is sent by the verifier to the prover to initiate a proof of a particular type, with the
 * corresponding input indexes to be used for this proof.
 * Note that the current support is for the GeoLocation separation proof type and the vertex indexes.
 */
public class ProofRequest implements Serializable {
    private static final long serialVersionUID = 4778883066023763026L;
    private final ProofType proofType;
    private final Vector<Integer> indexes;

    public ProofRequest(ProofType proofType, Vector<Integer> indexes) {

        this.proofType = proofType;
        this.indexes = indexes;
    }

    public ProofType getProofType() {
        return proofType;
    }

    public Vector<Integer> getIndexes() {
        return indexes;
    }

}
