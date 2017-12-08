package eu.prismacloud.primitives.grs.keys;

import eu.prismacloud.primitives.grs.signature.EncodingSignature;

/**
 * Created by Ioannis Sfyrakis on 29/07/2017
 */


public class GSExtendedKeyPair implements
        IGSExtendedKeyPair {
    private ExtendedPublicKey extendedPublicKey;
    private ExtendedPrivateKey extendedPrivateKey;

    public EncodingSignature getEncodingSignature() {
        return encodingSignature;
    }

    private EncodingSignature encodingSignature;

    public ExtendedPublicKey getPublicKey() {
        return null;
    }

    public ExtendedPrivateKey getPrivateKey() {
        return null;
    }
}
