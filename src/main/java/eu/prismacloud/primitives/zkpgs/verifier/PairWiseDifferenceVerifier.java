package eu.prismacloud.primitives.zkpgs.verifier;

import java.math.BigInteger;
import java.util.logging.Logger;

import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

public class PairWiseDifferenceVerifier implements IVerifier{
	public static final String URNID = "pairwisedifferenceverifier";
	
	private ExtendedPublicKey epk;
	  private ProofStore<Object> proofStore;
	  private KeyGenParameters keyGenParameters;
	  private GroupElement baseS;
	  private GroupElement baseR;
	  private GSCommitment C_i;
	  private GSCommitment C_j;
	  private int index;
	  
	  private BigInteger hata_BariBarj, hatb_BariBarj, hatr_BariBarj;
	  
	  private GroupElement hatR;
	  
	  private BigInteger cChallenge;

	  private Logger log = GSLoggerConfiguration.getGSlog();

	  public PairWiseDifferenceVerifier() {}
	  
	  public PairWiseDifferenceVerifier(final int index,
			  							GSCommitment C_i, GSCommitment C_j) {
		  this.index = index;
		  this.C_i = C_i;
		  this.C_j = C_j;
	  }
	  
	  /**
	   * Checks the lengths of the hat-values as inputs of the verifier.
	   * 
	   * @return <tt>true</tt> if and only if the inputs are in the specified range.
	   */
	  public boolean checkLengths() {
	    int l_hatab = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();
	    int l_hatr = keyGenParameters.getL_n() + keyGenParameters.getL_statzk() 	// size of commitment randomness r
				   + keyGenParameters.getL_m() 										// max size of a Bezout coefficient for a commitment message
				   + 1 																// accounting adding two blinding compensations
				   + keyGenParameters.getProofOffset();								// offset introduced by the challenge and response computation

	    hata_BariBarj = (BigInteger) proofStore.retrieve(getVerifierURN(URNType.HATABARIBARJ, index));
	    hatb_BariBarj = (BigInteger) proofStore.retrieve(getVerifierURN(URNType.HATBBARIBARJ, index));
	    hatr_BariBarj = (BigInteger) proofStore.retrieve(getVerifierURN(URNType.HATRBARIBARJ, index));
	    
//	    log.info("Desired BL for ab = " + l_hatab
//	    		+ "\n  hata (BL = " + hata_BariBarj.bitLength() + ") = " + hata_BariBarj
//	    		+ "\n  hatb (BL = " + hatb_BariBarj.bitLength() + ") = " + hatb_BariBarj
//	    		+ "\nDesired BL for v = " + l_hatr
//	    		+ "\n  hatr (BL = " + hatr_BariBarj.bitLength() + ") = " + hatr_BariBarj);

	    return CryptoUtilsFacade.isInPMRange(hata_BariBarj, l_hatab)
	        && CryptoUtilsFacade.isInPMRange(hatb_BariBarj, l_hatab)
	        && CryptoUtilsFacade.isInPMRange(hatr_BariBarj, l_hatr);
	  }

	  /**
	   * Computes the overall verification witness hatR for the PairWiseDifferenceVerifier.
	   * 
	   * @param extendedPublicKey
	   * @param proofStore
	   * @param keyGenParameters
	   * @return
	   */
	  public GroupElement computeHatR(
	      final ExtendedPublicKey extendedPublicKey,
	      final ProofStore<Object> proofStore,
	      final KeyGenParameters keyGenParameters) {

	    this.epk = extendedPublicKey;
	    this.proofStore = proofStore;
	    this.keyGenParameters = keyGenParameters;
	    this.baseS = epk.getPublicKey().getBaseS();
	    this.baseR = epk.getPublicKey().getBaseR();

	    hata_BariBarj = (BigInteger) proofStore.retrieve(getVerifierURN(URNType.HATABARIBARJ, index));
	    hatb_BariBarj = (BigInteger) proofStore.retrieve(getVerifierURN(URNType.HATBBARIBARJ, index));
	    hatr_BariBarj = (BigInteger) proofStore.retrieve(getVerifierURN(URNType.HATRBARIBARJ, index));
	    cChallenge = (BigInteger) proofStore.retrieve("verifier.c");

	    // Aborting verification with output null, if lengths check rejects hat-values.
	    if (!checkLengths()) return null;

	    // Computing Bezout's identity on the commitments
	    GroupElement C_iHata = C_i.getCommitmentValue().modPow(hata_BariBarj);
	    GroupElement C_jHatb = C_j.getCommitmentValue().modPow(hatb_BariBarj);
	    Assert.notNull(C_iHata, "C_i commitment computation turned out null.");
	    Assert.notNull(C_iHata, "C_j commitment computation turned out null.");
	    
	    // Adjusting the blinding randomness
	    GroupElement baseShatR = baseS.modPow(hatr_BariBarj);
	    Assert.notNull(baseShatR, "Blinding adjustment commitment computation turned out null.");
	    
	    // Cancelling out the challenge
	    GroupElement baseRnegC = baseR.modPow(cChallenge.negate()); 
	    Assert.notNull(baseRnegC, "Challenge negation returned null.");

	    this.hatR = baseRnegC.multiply(C_iHata).multiply(C_jHatb).multiply(baseShatR);
	    Assert.notNull(this.hatR, "hatR computed was null.");
//
//	    gslog.info("hatR: " + hatR
//	    		+ "\nhatR bitlength: " + hatR.bitLength());

	    return this.hatR;
	  }
	
		public String getVerifierURN(URNType t) {
			  if (URNType.isEnumerable(t)) {
				  throw new RuntimeException("URNType " + t + " is enumerable and should be evaluated with an index.");
			  }
			  return PairWiseDifferenceVerifier.URNID + "." + URNType.getClass(t) + "." + URNType.getSuffix(t);
		  }
		  
		  public String getVerifierURN(URNType t, int index) {
			  if (!URNType.isEnumerable(t)) {
				  throw new RuntimeException("URNType " + t + " is not enumerable and should not be evaluated with an index.");
			  }
			  return PairWiseDifferenceVerifier.URNID + "." + URNType.getClass(t) + "." + URNType.getSuffix(t) + index;
		  }
}
