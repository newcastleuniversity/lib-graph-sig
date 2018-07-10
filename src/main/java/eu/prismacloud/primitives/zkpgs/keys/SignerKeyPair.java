package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.KeyGenSignature;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupPQ;
import eu.prismacloud.primitives.zkpgs.util.crypto.SpecialRSAMod;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.logging.Logger;

/** Generates key pair for the Signer */
public class SignerKeyPair implements Serializable {

  private static final long serialVersionUID = -5396481186679228018L;
  
  private SignerPrivateKey privateKey;
  private SignerPublicKey publicKey;
  private KeyGenParameters keyGenParameters;
  private KeyGenSignature keyGenSignature;
  private SpecialRSAMod specialRSAMod = null;
  private GroupElement S;
  private BigInteger x_Z;
  private BigInteger x_R;
  private BigInteger x_R0;
  private GroupElement R;
  private GroupElement R_0;
  private GroupElement Z;
  private Group cg;
//  private final Logger log = GSLoggerConfiguration.getGSlog();
  private Group qrGroup;

  /**
   * Gets key gen signature.
   *
   * @return the key gen signature
   */
  public KeyGenSignature getKeyGenSignature() {
    return keyGenSignature;
  }

  /**
   * Generate a key pair for the signer.
   *
   * @return GSSignerKeyPair gs signer key pair
   */
  public void keyGen(KeyGenParameters keyGenParams) {
    keyGenParameters = keyGenParams;
    specialRSAMod = CryptoUtilsFacade.computeSpecialRSAModulus(keyGenParameters);

//    log.info("specialRSAmod: " + specialRSAMod);
    
    qrGroup = new QRGroupPQ(specialRSAMod.getpPrime(), specialRSAMod.getqPrime());
    S = qrGroup.createGenerator();

    // ** TODO check if the computations with the group elements are correct
    x_Z = CryptoUtilsFacade.computeRandomNumber(KeyGenParameters.getKeyGenParameters().getL_n());
    Z = S.modPow(x_Z);

    x_R = CryptoUtilsFacade.computeRandomNumber(KeyGenParameters.getKeyGenParameters().getL_n());
    R = S.modPow(x_R);

    x_R0 = CryptoUtilsFacade.computeRandomNumber(KeyGenParameters.getKeyGenParameters().getL_n());
    R_0 = S.modPow(x_R0);

    cg = CryptoUtilsFacade.commitmentGroupSetup(keyGenParameters);
    
    privateKey =
        new SignerPrivateKey(
            specialRSAMod.getP(),
            specialRSAMod.getpPrime(),
            specialRSAMod.getQ(),
            specialRSAMod.getqPrime(),
            x_R,
            x_R0,
            x_Z);
    
    publicKey = new SignerPublicKey(specialRSAMod.getN(), R, R_0, S, Z, keyGenParameters);

  }

  public SignerPrivateKey getPrivateKey() {
    return privateKey;
  }

  public SignerPublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Gets qr group.
   *
   * @return the qr group
   */
  public Group getQRGroup() {
    return qrGroup;
  }
}
