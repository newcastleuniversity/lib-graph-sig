package eu.prismacloud.primitives.grs.keys;

import eu.prismacloud.primitives.grs.parameters.KeyGenParameters;

import java.math.BigInteger;

/**
 * Created by Ioannis Sfyrakis on 25/07/2017
 */
public class SignerPublicKey {

    private  SignerPrivateKey privateKey;
    private BigInteger N;
    private BigInteger R_0;
    private BigInteger S;
    private BigInteger Z;

    public SignerPublicKey(final SignerPrivateKey privateKey, final KeyGenParameters gs_params){

        /* TODO add unique identifier to key */
        /* TODO initialize and Compute public key for signer */

        this.privateKey = privateKey;
       // this.gs_params = gs_params;

    }

    public SignerPublicKey() {

        privateKey = null;
    }

    public SignerPublicKey(final BigInteger N, final BigInteger R_0, final BigInteger S, final BigInteger Z) {
        this.N = N;
        this.R_0 = R_0;
        this.S = S;
        this.Z = Z;
    }


//	public AbstractParams getGs_params() {
//        return gs_params;
 //   }
}
