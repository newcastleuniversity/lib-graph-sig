package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.EEAlgorithm;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/** The type Pair wise difference prover. */
public class PairWiseDifferenceProver implements IProver {

	public static final String URNID = "pairwiseprover";

	private BigInteger m_Bari;
	private BigInteger m_Barj;
	private BigInteger r_Bari;
	private BigInteger r_Barj;
	private KeyGenParameters keyGenParameters;
	private GSCommitment C_j;
	private GSCommitment C_i;
	private ExtendedPublicKey epk;
	private GroupElement baseS;
	private GroupElement baseR;

	private ProofStore<Object> proofStore;
	private int index;
	private BigInteger a_BariBarj;
	private BigInteger b_BariBarj;
	private BigInteger d_BariBarj;
	private BigInteger r_BariBarj;
	private BigInteger tildea_BariBarj;
	private BigInteger tildeb_BariBarj;
	private BigInteger tilder_BariBarj;
	private BigInteger hata_BariBarj;
	private BigInteger hatb_BariBarj;
	private BigInteger hatr_BariBarj;
	private GroupElement basetildeR_BariBarj;
	private BigInteger c;
	private String a_BariBarjURN;
	private String b_BariBarjURN;
	private String r_BariBarjURN;
	private String tildea_BariBarjURN;
	private String tildeb_BariBarjURN;
	private String tilder_BariBarjURN;

	Logger gslog = GSLoggerConfiguration.getGSlog();
	private String basetildeR_BariBarjURN;

	/**
	 * Initiates as PairWiseDifferenceProver with two commitments as foundations.
	 * 
	 * @param C_i First commitment, associated with a
	 * @param C_j Second commitment, associated with b
	 * @param extendedPublicKey Signer's ExtendedPublicKey
	 * @param index Index of the PairWiseDifferenceProver to store its values in the ProofStore 
	 * @param proofStore
	 * @param keyGenParameters
	 */
	public PairWiseDifferenceProver(
			GSCommitment C_i,
			GSCommitment C_j,
			ExtendedPublicKey extendedPublicKey,
			int index,
			ProofStore<Object> proofStore,
			KeyGenParameters keyGenParameters) {

		Assert.notNull(C_i, "commitment i must not be null");
		Assert.notNull(C_j, "commitment j must not be null");
		Assert.notNull(C_i.getExponents(), "commitment  message must not be null");
		Assert.notNull(C_i.getRandomness(), "commitment randomness must not be null");
		Assert.notNull(C_j.getExponents(), "commitment message must not be null");
		Assert.notNull(C_j.getRandomness(), "commitment randomness must not be null");
		Assert.notNull(index, "component prover index must not be null");
		Assert.notNull(proofStore, "ProofStore must not be null");
		Assert.notNull(keyGenParameters, "keygen parameters must not be null");

		this.C_i = C_i;
		this.C_j = C_j;
		this.epk = extendedPublicKey;
		this.baseS = epk.getPublicKey().getBaseS();
		this.baseR = epk.getPublicKey().getBaseR();
		this.m_Bari = C_i.getExponents().get(URN.createZkpgsURN("commitment.exponent.m"));
		this.r_Bari = C_i.getRandomness();
		this.m_Barj = C_j.getExponents().get(URN.createZkpgsURN("commitment.exponent.m"));
		this.r_Barj = C_j.getRandomness();
		this.index = index;
		this.proofStore = proofStore;
		this.keyGenParameters = keyGenParameters;
	}

	public PairWiseDifferenceProver() {}

	
	public GroupElement preChallengePhase(GSCommitment C_i,
			GSCommitment C_j,
			ExtendedPublicKey extendedPublicKey,
			int index,
			ProofStore<Object> proverStore,
			KeyGenParameters keyGenParameters) {

		Assert.notNull(C_i, "commitment i must not be null");
		Assert.notNull(C_j, "commitment j must not be null");
		Assert.notNull(index, "component prover index must not be null");
		Assert.notNull(proverStore, "Prover store must not be null");
		Assert.notNull(keyGenParameters, "keygen parameters must not be null");

		this.C_i = C_i;
		this.C_j = C_j;
		this.epk = extendedPublicKey;
		this.baseS = epk.getPublicKey().getBaseS();
		this.baseR = epk.getPublicKey().getBaseR();
		this.m_Bari = C_i.getExponents().get(URN.createZkpgsURN("commitment.C_i"));
		this.r_Bari = C_i.getRandomness();
		this.m_Barj = C_j.getExponents().get(URN.createZkpgsURN("commitment.C_j"));
		this.r_Barj = C_j.getRandomness();
		this.index = index;
		this.proofStore = proverStore;
		this.keyGenParameters = keyGenParameters;
		
		createWitnessRandomness();
		
		return computeWitness();
	}
	
	/** Precomputation. @throws Exception the exception */
	@Override
	public void executePrecomputation() throws ProofStoreException {

		computeEEA();
		if (!d_BariBarj.equals(BigInteger.ONE)) {
			throw new IllegalArgumentException("messages are not coprime");
		}

		r_BariBarj = computeDifferentialRandomness();

		storeCoprimality();
	}

	private void storeCoprimality() throws ProofStoreException {
		a_BariBarjURN = "pairwiseprover.secret.a_BariBarj_" + index;
		
		b_BariBarjURN = "pairwiseprover.secret.b_BariBarj_" + index;

		r_BariBarjURN = "pairwiseprover.secret.r_BariBarj_" + index;

		proofStore.store(a_BariBarjURN, a_BariBarj);
		proofStore.store(b_BariBarjURN, b_BariBarj);
		proofStore.store(r_BariBarjURN, r_BariBarj);
	}

	/**
	 * Gets r bari barj.
	 *
	 * @return the r bari barj
	 */
	public BigInteger getR_BariBarj() {
		return this.r_BariBarj;
	}

	
	
	/**
	 * Gets c j.
	 *
	 * @return the c j
	 */
	public GSCommitment getC_j() {
		return this.C_j;
	}

	/**
	 * Gets c i.
	 *
	 * @return the c i
	 */
	public GSCommitment getC_i() {
		return this.C_i;
	}

	/**
	 * Gets tildea bari barj.
	 *
	 * @return the tildea bari barj
	 */
	public BigInteger getTildea_BariBarj() {
		return this.tildea_BariBarj;
	}

	/**
	 * Gets tildeb bari barj.
	 *
	 * @return the tildeb bari barj
	 */
	public BigInteger getTildeb_BariBarj() {
		return this.tildeb_BariBarj;
	}

	/**
	 * Gets tilder bari barj.
	 *
	 * @return the tilder bari barj
	 */
	//  public BigInteger getTilder_BariBarj() {
	//    return this.tilder_BariBarj;
	//  }

	/** Compute eea. */
	public void computeEEA() {
		EEAlgorithm.computeEEAlgorithm(m_Bari, m_Barj);
		System.out.println("EEA Inputs: "
				+ "\n i : " + m_Bari
				+ "\n j : " + m_Barj);
		
		this.d_BariBarj = EEAlgorithm.getD();
		this.a_BariBarj = EEAlgorithm.getS();
		this.b_BariBarj = EEAlgorithm.getT();
		
		System.out.println("EEA Outputs: "
				+ "\n d = " + d_BariBarj
				+ "\n a = " + a_BariBarj
				+ "\n b = " + b_BariBarj);
	}

	/**
	 * Compute differential randomness big integer.
	 *
	 * @return the big integer
	 */
	public BigInteger computeDifferentialRandomness() {
		return (r_Bari.negate().multiply(a_BariBarj)).subtract(r_Barj.multiply(b_BariBarj));
	}

	/**
	 * Gets a bari barj.
	 *
	 * @return the a bari barj
	 */
	public BigInteger getA_BariBarj() {
		return this.a_BariBarj;
	}

	/**
	 * Gets b bari barj.
	 *
	 * @return the b bari barj
	 */
	public BigInteger getB_BariBarj() {
		return this.b_BariBarj;
	}

	/**
	 * Gets d bari barj.
	 *
	 * @return the d bari barj
	 */
	public BigInteger getD_BariBarj() {
		return this.d_BariBarj;
	}

	@Override
	public void createWitnessRandomness() {
		int randomnessLength =
				keyGenParameters.getL_n() + keyGenParameters.getProofOffset();
		tildea_BariBarj = CryptoUtilsFacade.computeRandomNumber(randomnessLength);
		tildeb_BariBarj = CryptoUtilsFacade.computeRandomNumber(randomnessLength);
		tilder_BariBarj = CryptoUtilsFacade.computeRandomNumber(randomnessLength);

		storeWitnessRandomness();
	}

	private void storeWitnessRandomness() {
		tildea_BariBarjURN = "pairwiseprover.witnesses.randomness.tildea_BariBarj_" + index;

		tildeb_BariBarjURN = "pairwiseprover.witnesses.randomness.tildeb_BariBarj_" + index;

		tilder_BariBarjURN = "pairwiseprover.witnesses.randomness.tilder_BariBarj_" + index;
		try {
			proofStore.store(tildea_BariBarjURN, tildea_BariBarj);
			proofStore.store(tildeb_BariBarjURN, tildeb_BariBarj);
			proofStore.store(tilder_BariBarjURN, tilder_BariBarj);
		} catch (Exception e) {
			gslog.log(Level.SEVERE, e.getMessage());
		}
	}

	@Override
	public GroupElement computeWitness() {
		GroupElement C_Bari = C_i.getCommitmentValue();
		GroupElement C_Barj = C_j.getCommitmentValue();

		basetildeR_BariBarj =
				C_Bari.modPow(tildea_BariBarj)
				.multiply(
						C_Bari.modPow(tildeb_BariBarj).multiply(baseS.modPow(tilder_BariBarj)));

		storeWitness();
		return basetildeR_BariBarj;
	}

	private void storeWitness() {
		basetildeR_BariBarjURN = "pairwiseprover.basetildeR_BariBarj_" + index;
		try {
			proofStore.store(tildea_BariBarjURN, basetildeR_BariBarj);
		} catch (Exception e) {
			gslog.log(Level.SEVERE, e.getMessage());
		}
	}

	  @Override
	  public BigInteger computeChallenge() throws NoSuchAlgorithmException {
	    return CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
	  }

	/**
	 * Sets challenge.
	 *
	 * @param challenge the challenge
	 */
	public void setChallenge(BigInteger challenge) {
		this.c = challenge;
	}
	
	public void postChallengePhase(BigInteger challenge) {
		setChallenge(challenge);
		computeResponses();
	}

	@Override
	public void computeResponses() {
		a_BariBarj = (BigInteger) proofStore.retrieve(getProverURN(URNType.ABARIBARJ, index));

		b_BariBarj = (BigInteger) proofStore.retrieve(getProverURN(URNType.BBARIBARJ, index));

		r_BariBarj = (BigInteger) proofStore.retrieve(getProverURN(URNType.RBARIBARJ, index));

		
		hata_BariBarj = tildea_BariBarj.add(this.c.multiply(a_BariBarj));
		hatb_BariBarj = tildeb_BariBarj.add(this.c.multiply(b_BariBarj));
		hatr_BariBarj = tilder_BariBarj.add(this.c.multiply(r_BariBarj));
		
		storeResponses();
	}

	private void storeResponses() {
		String hata_BariBarjURN = "pairwiseprover.responses.hata_BariBarj_" + index;
		String hatb_BariBarjURN = "pairwiseprover.responses.hatb_BariBarj_" + index;
		String hatr_BariBarjURN = "pairwiseprover.responses.hatr_BariBarj_" + index;

		try {
			proofStore.store(hata_BariBarjURN, hata_BariBarj);
			proofStore.store(hatb_BariBarjURN, hatb_BariBarj);
			proofStore.store(hatr_BariBarjURN, hatr_BariBarj);
		} catch (Exception e) {
			gslog.log(Level.SEVERE, e.getMessage());
		}
	}

	/**
	 * Gets hata bari barj.
	 *
	 * @return the hata bari barj
	 */
	public BigInteger getHata_BariBarj() {
		return this.hata_BariBarj;
	}

	/**
	 * Gets hatb bari barj.
	 *
	 * @return the hatb bari barj
	 */
	public BigInteger getHatb_BariBarj() {
		return this.hatb_BariBarj;
	}

	/**
	 * Gets hatr bari barj.
	 *
	 * @return the hatr bari barj
	 */
	public BigInteger getHatr_BariBarj() {
		return this.hatr_BariBarj;
	}

	/**
	 * Gets tilde r bari barj.
	 *
	 * @return the tilde r bari barj
	 */
	public GroupElement getBasetildeR_BariBarj() {
		return basetildeR_BariBarj;
	}

	@Override
	public boolean verify() {
		// Compute the verification equation from the prover's point of view.
		// The results should be equal to tildeR of the pre-challenge phase.
		GroupElement C_iHata = C_i.getCommitmentValue().modPow(hata_BariBarj);
		GroupElement C_jHatb = C_j.getCommitmentValue().modPow(hatb_BariBarj);
		GroupElement blindingAdjustment = baseS.modPow(hatr_BariBarj);

		// Cancelling out the challenge
		GroupElement baseRnegChallenge = baseR.modPow(c.negate());

		GroupElement verifier = baseRnegChallenge.multiply(C_iHata).multiply(C_jHatb).multiply(blindingAdjustment);

		return verifier.equals(this.basetildeR_BariBarj);
	}
	
	public String getProverURN(URNType t) {
		  if (URNType.isEnumerable(t)) {
			  throw new RuntimeException("URNType " + t + " is enumerable and should be evaluated with an index.");
		  }
		  return PairWiseDifferenceProver.URNID + "." + URNType.getClass(t) + "." + URNType.getSuffix(t);
	  }
	  
	  public String getProverURN(URNType t, int index) {
		  if (!URNType.isEnumerable(t)) {
			  throw new RuntimeException("URNType " + t + " is not enumerable and should not be evaluated with an index.");
		  }
		  return PairWiseDifferenceProver.URNID + "." + URNType.getClass(t) + "." + URNType.getSuffix(t) + index;
	  }
}
