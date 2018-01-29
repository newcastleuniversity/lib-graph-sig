package eu.prismacloud.primitives.grs;

import eu.prismacloud.primitives.grs.keys.IGSExtendedKeyPair;
import eu.prismacloud.primitives.grs.signature.EncodingSignature;


public class GSGraphEncodingResult {

    private IGSExtendedKeyPair extendedKeyGenPair;
    private EncodingSignature signature;

    public GSGraphEncodingResult() {
    }

    public IGSExtendedKeyPair getExtendedKeyGenPair() {
        return extendedKeyGenPair;
    }

    public EncodingSignature getSignature() {
        return signature;
    }

    public void setSignature(EncodingSignature signature) {
        this.signature = signature;
    }


}
