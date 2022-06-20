package uk.ac.ncl.cascade.zkpgs.keys;

import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.store.URN;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Map;

public class ExtendedPrivateKey implements IPrivateKey, Serializable {

 
   /**
	 * 
	 */
	private static final long serialVersionUID = -3866724172008302196L;
	
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
