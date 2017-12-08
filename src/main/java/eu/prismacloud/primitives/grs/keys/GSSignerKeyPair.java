package eu.prismacloud.primitives.grs.keys;

import eu.prismacloud.primitives.grs.signature.KeyGenSignature;
import eu.prismacloud.primitives.grs.utils.CommitmentGroup;
import eu.prismacloud.primitives.grs.utils.CryptoUtilsFacade;
import eu.prismacloud.primitives.grs.utils.NumberConstants;
import eu.prismacloud.primitives.grs.utils.SpecialRSAMod;

import java.math.BigInteger;

/**
 * Generates key pair for the Signer
 */
public class GSSignerKeyPair implements IGSKeyPair {

    private SignerPrivateKey privateKey;
    private SignerPublicKey publicKey;
    private KeyGenSignature keyGenSignature;
    private SpecialRSAMod specialRSAMod;
    private BigInteger S;
    private BigInteger x_Z;
    private BigInteger x_R_0;
    private BigInteger R_0;
    private BigInteger Z;
    private CommitmentGroup cg;


    public GSSignerKeyPair(SignerPrivateKey privateKey, SignerPublicKey publicKey) {
        this.privateKey = new SignerPrivateKey();
        this.publicKey = new SignerPublicKey();
    }


    public KeyGenSignature getKeyGenSignature() {
        return this.keyGenSignature;
    }

    /**
     * Generate a key pair for the signer.
     *
     * @return GSSignerKeyPair
     */
    public GSSignerKeyPair KeyGen() {
        specialRSAMod = CryptoUtilsFacade.computeSpecialRSAModulus();
        S = CryptoUtilsFacade.computeQRNGenerator(specialRSAMod.getN());
        BigInteger upperBound = specialRSAMod.getP_prime().multiply(specialRSAMod.getQ_prime()).subtract(BigInteger.ONE);
        x_Z = CryptoUtilsFacade.computeRandomNumber(NumberConstants.TWO.getValue(), upperBound);
        Z = S.modPow(x_Z, specialRSAMod.getN());
        x_R_0 = CryptoUtilsFacade.computeRandomNumber(NumberConstants.TWO.getValue(), upperBound);
        R_0 = S.modPow(x_R_0, specialRSAMod.getN());
        cg = CryptoUtilsFacade.commitmentGroupSetup();
        privateKey = new SignerPrivateKey(specialRSAMod.getP(), specialRSAMod.getP_prime(), specialRSAMod.getQ(), specialRSAMod.getQ_prime(), x_R_0, x_Z);
        publicKey = new SignerPublicKey(specialRSAMod.getN(), R_0, S, Z);

        return new GSSignerKeyPair(privateKey, publicKey);

    }

    public void generateKeySignature() {
        /* TODO generate key signature */
    }


    public SignerPrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public SignerPublicKey getPublicKey() {
        return this.publicKey;
    }

    public KeyGenSignature getSignature() {
        // TODO Auto-generated method stub
        return null;
    }

    public CommitmentGroup getCommitmentGroup() {
        return cg;
    }
}
