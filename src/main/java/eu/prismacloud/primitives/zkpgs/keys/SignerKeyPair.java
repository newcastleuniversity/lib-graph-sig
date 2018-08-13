package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroup;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupPQ;
import eu.prismacloud.primitives.zkpgs.util.crypto.SpecialRSAMod;
import java.io.Serializable;
import java.math.BigInteger;

/** Generates key pair for the Signer */
public class SignerKeyPair implements Serializable {

  private static final long serialVersionUID = -5396481186679228018L;
  private SignerPrivateKey privateKey;
  private SignerPublicKey publicKey;
  private KeyGenParameters keyGenParameters;
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
  private QRGroup qrGroup;


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
    x_Z = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_n());
    Z = S.modPow(x_Z);

    x_R = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_n());
    R = S.modPow(x_R);

    x_R0 = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_n());
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
            x_Z, (QRGroup) qrGroup);
    
    publicKey = new SignerPublicKey(specialRSAMod.getN(), R, R_0, S, Z, qrGroup, keyGenParameters);

  }

  public SignerPrivateKey getPrivateKey() {
    return privateKey;
  }

  public SignerPublicKey getPublicKey() {
    return publicKey;
  }

}
