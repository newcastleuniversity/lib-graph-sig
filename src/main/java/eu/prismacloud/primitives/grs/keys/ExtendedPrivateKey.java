package eu.prismacloud.primitives.grs.keys;

import java.math.BigInteger;
import java.util.Vector;


public abstract class ExtendedPrivateKey {

    final ISignerPrivateKey signerPrivateKey;
    Vector<BigInteger> discreteLogarithms;


    public ExtendedPrivateKey(final ISignerPrivateKey signerPrivateKey) {

        this.signerPrivateKey = signerPrivateKey;
    }

    public Vector<BigInteger> getDiscreteLogarithms() {
        return discreteLogarithms;
    }


    public ExtendedPrivateKey getPrivateKey() {
        return null;
    }
}
