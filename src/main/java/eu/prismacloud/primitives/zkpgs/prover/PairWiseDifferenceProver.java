package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.EnumeratedURNType;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.EEAlgorithm;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/** 
 * The PairWiseDifferenceProver is a component prover, 
 * which shows that the committed values of a pair of commitments
 * are coprime.
 * 
 * <p>The PairWiseDifferenceProver has a pre-computation phase, called with 
 * executePrecomputation(), which establishes the coefficients of Bezout's identity.
 * For messages {@code m_i} and {@code m_j} we will have that
 * {@code EAA(m_i, m_j) = (d, s, t)}, such that
 * {@code s*m_i + t*m_j = d}.
 * 
 * <p>This equation has a unique solution for {@code d=1} if and only if
 * {@code m_j} and {@code m_j} are coprime. 
 * */
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
	private BigInteger cChallenge;
	private String a_BariBarjURN;
	private String b_BariBarjURN;
	private String r_BariBarjURN;
	private String tildea_BariBarjURN;
	private String tildeb_BariBarjURN;
	private String tilder_BariBarjURN;
	private String basetildeR_BariBarjURN;
	
	private List<URNType> urnTypes;
	private List<EnumeratedURNType> enumeratedTypes;
	private List<URN> governedURNs;

	Logger gslog = GSLoggerConfiguration.getGSlog();

	/**
	 * Initiates as PairWiseDifferenceProver with two commitments as foundations.
	 * 
	 * @param C_i First commitment, associated with a
	 * @param C_j Second commitment, associated with b
	 * @param index Index of the PairWiseDifferenceProver to store its values in the ProofStore 
	 * @param extendedPublicKey Signer's ExtendedPublicKey
	 * @param proofStore the proof store for storing or retrieving elements
	 */
	// TODO Refactor to dual indexing for commitment pairs.
	public PairWiseDifferenceProver(
			GSCommitment C_i,
			GSCommitment C_j,
			int index,
			ExtendedPublicKey extendedPublicKey,
			ProofStore<Object> proofStore) {

		Assert.notNull(C_i, "commitment i must not be null");
		Assert.notNull(C_j, "commitment j must not be null");
		Assert.notNull(C_i.getRandomness(), "commitment randomness must not be null");
		Assert.notNull(C_j.getRandomness(), "commitment randomness must not be null");
		Assert.notNull(C_i.getBaseCollection(), "the base collection must not be null");
		Assert.notNull(C_j.getBaseCollection(), "the base collection must not be null");
		Assert.notNull(index, "component prover index must not be null");
		Assert.notNull(proofStore, "ProofStore must not be null");

		this.C_i = C_i;
		this.C_j = C_j;
		this.epk = extendedPublicKey;
		this.baseS = epk.getPublicKey().getBaseS();
		this.baseR = epk.getPublicKey().getBaseR();
		this.m_Bari = C_i.getBaseCollection().getFirst().getExponent();
		this.r_Bari = C_i.getRandomness();
		this.m_Barj = C_j.getBaseCollection().getFirst().getExponent();
		this.r_Barj = C_j.getRandomness();
		this.index = index;
		this.proofStore = proofStore;
		this.keyGenParameters = this.epk.getKeyGenParameters();
	}

	public PairWiseDifferenceProver() {}


	@Override
	public Map<URN, GroupElement> executeCompoundPreChallengePhase() throws ProofStoreException {
		GroupElement witness = executePreChallengePhase();
		Map<URN, GroupElement> witnesses = new HashMap<>();
		witnesses.put(URN.createZkpgsURN(basetildeR_BariBarjURN), witness);
		return witnesses;
	}
	
	@Override
	public GroupElement executePreChallengePhase() throws ProofStoreException {
		createWitnessRandomness();

		return computeWitness();
	}

	@Override
	public void executePrecomputation() throws ProofStoreException {

		computeEEA();
		if (!d_BariBarj.equals(BigInteger.ONE)) {
			throw new IllegalArgumentException("Messages are not coprime");
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
	private void computeEEA() {
		EEAlgorithm.computeEEAlgorithm(m_Bari, m_Barj);
		//		System.out.println("EEA Inputs: "
		//				+ "\n i : " + m_Bari
		//				+ "\n j : " + m_Barj);

		this.d_BariBarj = EEAlgorithm.getD();
		this.a_BariBarj = EEAlgorithm.getS();
		this.b_BariBarj = EEAlgorithm.getT();

		//		System.out.println("EEA Outputs: "
		//				+ "\n d = " + d_BariBarj
		//				+ "\n a = " + a_BariBarj
		//				+ "\n b = " + b_BariBarj
		//				+ "\n ai + bj = " + (m_Bari.multiply(a_BariBarj)).add(m_Barj.multiply(b_BariBarj)));
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

	private void createWitnessRandomness() {
		int l_tildeab =
				keyGenParameters.getL_n() + keyGenParameters.getProofOffset();
		int l_tilder =
				keyGenParameters.getL_n() + keyGenParameters.getL_statzk() 	// size of commitment randomness r
				+ keyGenParameters.getL_m() 									// max size of a Bezout coefficient for a commitment message
				+ keyGenParameters.getProofOffset();							// offset introduced by the challenge and response computation

		tildea_BariBarj = CryptoUtilsFacade.computeRandomNumber(l_tildeab);
		tildeb_BariBarj = CryptoUtilsFacade.computeRandomNumber(l_tildeab);
		tilder_BariBarj = CryptoUtilsFacade.computeRandomNumber(l_tilder);

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

	private GroupElement computeWitness() {
		GroupElement C_Bari = C_i.getCommitmentValue();
		GroupElement C_Barj = C_j.getCommitmentValue();

		basetildeR_BariBarj =
				C_Bari.modPow(tildea_BariBarj)
				.multiply(
						C_Barj.modPow(tildeb_BariBarj)).
				multiply(baseS.modPow(tilder_BariBarj));

		storeWitness();


		return basetildeR_BariBarj;
	}

	private void storeWitness() {
		basetildeR_BariBarjURN = "pairwiseprover.tildeBaseR_BariBarj_" + index;
		try {
			proofStore.store(basetildeR_BariBarjURN, basetildeR_BariBarj);
		} catch (Exception e) {
			gslog.log(Level.SEVERE, e.getMessage());
		}
	}

	public BigInteger computeChallenge() throws NoSuchAlgorithmException {
		return CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
	}

	/**
	 * Sets challenge.
	 *
	 * @param challenge the challenge
	 */
	private void setChallenge(BigInteger challenge) {
		this.cChallenge = challenge;
	}

	@Override
	public Map<URN, BigInteger> executePostChallengePhase(BigInteger cChallenge) throws ProofStoreException {
		setChallenge(cChallenge);
		return computeResponses();
	}

	private Map<URN, BigInteger> computeResponses() {
		Map<URN, BigInteger> responses = new HashMap<URN, BigInteger>();
		a_BariBarj = (BigInteger) proofStore.retrieve(getProverURN(URNType.ABARIBARJ, index));

		b_BariBarj = (BigInteger) proofStore.retrieve(getProverURN(URNType.BBARIBARJ, index));

		r_BariBarj = (BigInteger) proofStore.retrieve(getProverURN(URNType.RBARIBARJ, index));


		hata_BariBarj = tildea_BariBarj.add(this.cChallenge.multiply(a_BariBarj));
		hatb_BariBarj = tildeb_BariBarj.add(this.cChallenge.multiply(b_BariBarj));
		hatr_BariBarj = tilder_BariBarj.add(this.cChallenge.multiply(r_BariBarj));

		String hata_BariBarjURN = "pairwiseprover.responses.hata_BariBarj_" + index;
		String hatb_BariBarjURN = "pairwiseprover.responses.hatb_BariBarj_" + index;
		String hatr_BariBarjURN = "pairwiseprover.responses.hatr_BariBarj_" + index;

		responses.put(URN.createZkpgsURN(hata_BariBarjURN), hata_BariBarj);
		responses.put(URN.createZkpgsURN(hatb_BariBarjURN), hatb_BariBarj);
		responses.put(URN.createZkpgsURN(hatr_BariBarjURN), hatr_BariBarj);
		
		storeResponses();
		
		return responses;
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

	/**
	 * Executes the self-verification of the PairWiseDifferenceProver, establishing
	 * that the hat-values produced indeed fulfill the verification equation.
	 * 
	 * @return <tt>true</tt> if and only if the hat-values would pass the verification equation.
	 */
	@Override
	public boolean verify() {
		// Compute the verification equation from the prover's point of view.
		// The results should be equal to tildeR of the pre-challenge phase.
		GroupElement C_iHata = C_i.getCommitmentValue().modPow(hata_BariBarj);
		GroupElement C_jHatb = C_j.getCommitmentValue().modPow(hatb_BariBarj);
		GroupElement blindingAdjustment = baseS.modPow(hatr_BariBarj);

		// Cancelling out the challenge
		GroupElement baseRnegChallenge = baseR.modPow(cChallenge.negate());

		GroupElement verifier = baseRnegChallenge.multiply(C_iHata).multiply(C_jHatb).multiply(blindingAdjustment);

		return verifier.equals(this.basetildeR_BariBarj);
	}

	public String getProverURN(URNType t) {
		if (URNType.isEnumerable(t)) {
			throw new IllegalArgumentException("URNType " + t + " is enumerable and should be evaluated with an index.");
		}
		return PairWiseDifferenceProver.URNID + "." + URNType.getNameSpaceComponentClass(t) + "." + URNType.getSuffix(t);
	}

	public String getProverURN(URNType t, int index) {
		if (!URNType.isEnumerable(t)) {
			throw new IllegalArgumentException("URNType " + t + " is not enumerable and should not be evaluated with an index.");
		}
		return PairWiseDifferenceProver.URNID + "." + URNType.getNameSpaceComponentClass(t) + "." + URNType.getSuffix(t) + index;
	}
	
	@Override
	public List<URN> getGovernedURNs() {
		if (urnTypes == null) {
			  urnTypes = Collections.emptyList();
		  }
		if (enumeratedTypes == null) {
		  enumeratedTypes = Collections.unmodifiableList(
				  Arrays.asList(
						(new EnumeratedURNType(URNType.ABARIBARJ, index)),
						(new EnumeratedURNType(URNType.BBARIBARJ, index)),
						(new EnumeratedURNType(URNType.RBARIBARJ, index)),
						(new EnumeratedURNType(URNType.TILDEABARIBARJ, index)),
						(new EnumeratedURNType(URNType.TILDEBBARIBARJ, index)),
						(new EnumeratedURNType(URNType.TILDERBARIBARJ, index)),
						(new EnumeratedURNType(URNType.HATABARIBARJ, index)),
						(new EnumeratedURNType(URNType.HATBBARIBARJ, index)),
						(new EnumeratedURNType(URNType.HATRBARIBARJ, index))
				  ));
		}
		if (governedURNs == null) {
			governedURNs = Collections.unmodifiableList(URNType.buildURNList(urnTypes, enumeratedTypes, this.getClass()));
		}
		  return governedURNs;
	  }
}
