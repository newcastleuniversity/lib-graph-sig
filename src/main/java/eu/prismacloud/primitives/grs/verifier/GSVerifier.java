package eu.prismacloud.primitives.grs.verifier;

import eu.prismacloud.primitives.grs.commitment.ICommitment;
import eu.prismacloud.primitives.grs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.grs.signature.GSGraphSignature;

import java.math.BigInteger;

/**
 * Created by Ioannis Sfyrakis on 20/07/2017
 */
public  class GSVerifier implements IVerifier{

    public Boolean verify(ExtendedPublicKey extendedPublicKey, ICommitment recCommitment, BigInteger rndVerifier, GSGraphSignature graphSignature) {
        return null;
    }

    public BigInteger generateNonce(){
        /* TODO compute nonce for verifier */
        return null;
    }
}
