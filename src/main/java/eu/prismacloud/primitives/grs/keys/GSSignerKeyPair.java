package eu.prismacloud.primitives.grs.keys;

import eu.prismacloud.primitives.grs.signature.KeyGenSignature;
import eu.prismacloud.primitives.grs.utils.*;

import java.math.BigInteger;
import java.util.logging.Logger;

/**
 * Generates key pair for the Signer
 */
public class GSSignerKeyPair implements IGSKeyPair {

    private static SignerPrivateKey privateKey;
    private static SignerPublicKey publicKey;
    private static KeyGenSignature keyGenSignature;
    private static SpecialRSAMod specialRSAMod = null;
    private static BigInteger S;
    private static BigInteger x_Z;
    private static BigInteger x_R_0;
    private static BigInteger R_0;
    private static BigInteger Z;
    private static CommitmentGroup cg;
    private static final Logger log = GSLoggerConfiguration.getGSlog();


    public GSSignerKeyPair(final SignerPrivateKey privateKey, final SignerPublicKey publicKey) {
        GSSignerKeyPair.privateKey = privateKey;
        GSSignerKeyPair.publicKey = publicKey;
    }


    public static KeyGenSignature getKeyGenSignature() {
        return keyGenSignature;
    }

    /**
     * Generate a key pair for the signer.
     *
     * @return GSSignerKeyPair
     */
    public static GSSignerKeyPair KeyGen() {

        specialRSAMod = CryptoUtilsFacade.computeSpecialRSAModulus();

        QRGroup qrGroup = new QRGroup(specialRSAMod.getP_prime(), specialRSAMod.getQ_prime());
        S = qrGroup.createGenerator().getValue();

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
        return privateKey;
    }

    public SignerPublicKey getPublicKey() {
        return publicKey;
    }

    public KeyGenSignature getSignature() {
        // TODO implement getSignature
        throw new RuntimeException("getSignature not implemented");
    }

}
