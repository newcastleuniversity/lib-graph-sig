package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.Map;

public class ExtendedPrivateKey implements IPrivateKey {

  private final SignerPrivateKey signerPrivateKey;
  private Map<URN, BigInteger> discLogOfBases;

  public ExtendedPrivateKey(
      SignerPrivateKey signerPrivateKey, Map<URN, BigInteger> discLogOfBases) {

    this.signerPrivateKey = signerPrivateKey;
    this.discLogOfBases = discLogOfBases;
  }

  public Map<URN, BigInteger> getDiscLogOfBases() {
    return discLogOfBases;
  }

  public SignerPrivateKey getPrivateKey() {
    return this.signerPrivateKey;
  }
  
  public KeyGenParameters getKeyGenParameters() {
	  return this.signerPrivateKey.getKeyGenParameters();
  }
}
