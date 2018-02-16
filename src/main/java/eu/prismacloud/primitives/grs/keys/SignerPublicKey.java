package eu.prismacloud.primitives.grs.keys;

import eu.prismacloud.primitives.grs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.grs.utils.GroupElement;

import java.math.BigInteger;


public class SignerPublicKey {

    private SignerPrivateKey privateKey;
    private BigInteger N;
    private BigInteger R_0;
    private GroupElement S;
    private BigInteger Z;

    public SignerPublicKey(final SignerPrivateKey privateKey, final KeyGenParameters gs_params){

        /* TODO add unique identifier to key */
        /* TODO initialize and Compute public key for signer */

        this.privateKey = privateKey;
       // this.gs_params = gs_params;

    }


    public SignerPublicKey(final BigInteger N, final BigInteger R_0, final GroupElement S, final BigInteger Z) {
        this.N = N;
        this.R_0 = R_0;
        this.S = S;
        this.Z = Z;
    }

    public BigInteger getN() {
        return N;
    }

    public BigInteger getR_0() {
        return R_0;
    }

    public GroupElement getS() {
        return S;
    }

    public BigInteger getZ() {
        return Z;
    }

}
