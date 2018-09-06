package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/** The type Commitment prover. */

// TODO Separate out issuing and proving phases.
public class CommitmentProver implements IProver {


	public static final String URNID = "commitmentprover";

	public enum STAGE {
		ISSUING,
		PROVING
	}

	private final Logger gslog = GSLoggerConfiguration.getGSlog();

	private final int index;
	private final ProofStore<Object> proofStore;
	private final SignerPublicKey signerPublicKey;
	private final KeyGenParameters keyGenParameters;
	private final GSCommitment com;
	private final GroupElement baseS;
	
	private final STAGE proofStage;

	private final BaseCollection baseCollection;

	private BigInteger cChallenge;

	private final Map<URN, BigInteger> responses = new LinkedHashMap<URN, BigInteger>();

	private BigInteger tildem_0;
	
	private BigInteger tildevPrime;
	
	private BigInteger tilder_i;

	/**
	 * Establishes a CommitmentProver for proving a commitment with a given index in Prove mode.
	 * 
	 * @param com The commitment to be proven.
	 * @param index The index of the commitment.
	 * @param spk The SignerPublicKey used.
	 * @param ps The ProofStore used.
	 */
	public CommitmentProver(
			final GSCommitment com, final int index, final SignerPublicKey spk, final ProofStore<Object> ps) {
		this.proofStage = STAGE.PROVING;
		
		Assert.notNull(com, "Commitment must not be null");
		Assert.notNull(index, "index must not be null");
		Assert.notNull(ps, "proof store must not be null");
		Assert.notNull(spk, "extended public key must not be null");

		this.signerPublicKey = spk;
		this.keyGenParameters = spk.getKeyGenParameters();
		this.baseS = spk.getBaseS();
		this.index = index;
		this.proofStore = ps;
		this.com = com;
		this.baseCollection = com.getBaseCollection();
	}
	
	/** 
	 * Establishes a CommitmentProver for the Sign mode, that is, a CommitmentProver 
	 * used by the Recipient to provide hidden (committed) values to the Signer.
	 * 
	 * @param com commitment to be proven.
	 * @param spk Signer Public Key to be used.
	 * @param ps ProofStore to be used.
	 */
	public CommitmentProver(
			final GSCommitment com, final SignerPublicKey spk, final ProofStore<Object> ps) {
		this.proofStage = STAGE.ISSUING;
		
		Assert.notNull(com, "Commitment must not be null");
		Assert.notNull(ps, "proof store must not be null");
		Assert.notNull(spk, "extended public key must not be null");

		this.signerPublicKey = spk;
		this.keyGenParameters = spk.getKeyGenParameters();
		this.baseS = spk.getBaseS();
		this.proofStore = ps;
		this.index = -1;
		this.com = com;
		this.baseCollection = com.getBaseCollection();
	}

	@Override
	public void executePrecomputation() {
		// NO PRE-COMPUTATION IS NEEDED: NO-OP.
	}

	/**
	 * Pre challenge phase for commitment prover in the proving stage.
	 *
	 * @return the gs commitment
	 */
	@Override
	public Map<URN, GroupElement> executeCompoundPreChallengePhase() throws ProofStoreException {
		Map<URN, GroupElement> witnesses = new HashMap<URN, GroupElement>(1);
		GroupElement witness = executePreChallengePhase();

		witnesses.put(URN.createZkpgsURN(
				(proofStage == STAGE.ISSUING)? 
						getProverURN(URNType.TILDEU) : 
							getProverURN(URNType.TILDECI, this.index)), 
				witness);

		return witnesses;
	}

	@Override
	public GroupElement executePreChallengePhase() throws ProofStoreException {
		createWitnessRandomness();
		return computeWitness();
	}

	private void createWitnessRandomness() throws ProofStoreException {
		if (proofStage == STAGE.ISSUING) {
			witnessRandomnessIssuing();
		} else {
			witnessRandomnessProving();
		}
	}

	private void witnessRandomnessIssuing() throws ProofStoreException {
		URN urnVertex;
		URN urnEdge;
		int tildevPrimeBitLength =
				keyGenParameters.getL_n()
				+ (2 * keyGenParameters.getL_statzk())
				+ keyGenParameters.getL_H();

		BigInteger tildevPrime = CryptoUtilsFacade.computeRandomNumberMinusPlus(tildevPrimeBitLength);
		String tildevPrimeURN = getProverURN(URNType.TILDEVPRIME);
		proofStore.store(tildevPrimeURN, tildevPrime);

		int mBitLength =
				keyGenParameters.getL_m() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;

		tildem_0 = CryptoUtilsFacade.computeRandomNumberMinusPlus(mBitLength);
		String tildem_0URN = getProverURN(URNType.TILDEM0);
		proofStore.store(tildem_0URN, tildem_0);

		Map<URN, BigInteger> vertexWitnessRandomness = new HashMap<URN, BigInteger>();

		if (baseCollection.size() > 1) {
			BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
			for (BaseRepresentation baseRepresentation : vertexIterator) {
				urnVertex = URN.createZkpgsURN(getProverURN(URNType.TILDEMI, baseRepresentation.getBaseIndex()));
				BigInteger tildem_i = CryptoUtilsFacade.computeRandomNumberMinusPlus(mBitLength);
				vertexWitnessRandomness.put(urnVertex, tildem_i);
				proofStore.store(getProverURN(URNType.TILDEMI, baseRepresentation.getBaseIndex()), tildem_i);
			}

			BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
			for (BaseRepresentation baseRepresentation : edgeIterator) {
				urnEdge = URN.createZkpgsURN(getProverURN(URNType.TILDEMIJ, baseRepresentation.getBaseIndex()));
				BigInteger tildem_i_j = CryptoUtilsFacade.computeRandomNumberMinusPlus(mBitLength);
				vertexWitnessRandomness.put(urnEdge, tildem_i_j);
				proofStore.store(getProverURN(URNType.TILDEMIJ, baseRepresentation.getBaseIndex()), tildem_i_j);
			}
		}
	}

	private void witnessRandomnessProving() throws ProofStoreException {
		int tilder_iLength = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();

		BigInteger tilder_i = CryptoUtilsFacade.computeRandomNumber(tilder_iLength);

		String tilder_iURN = getProverURN(URNType.TILDERI, index);

		proofStore.store(tilder_iURN, tilder_i);
	}

	public GroupElement computeWitness() {
		Map<URN, GroupElement> baseMap = new HashMap<>();
		Map<URN, BigInteger> exponentsMap = new HashMap<>();

		GroupElement R_0 = signerPublicKey.getBaseR_0();

		if (proofStage == STAGE.ISSUING) {
			baseMap.put(URN.createZkpgsURN("commitment.R_0"), R_0);
			exponentsMap.put(URN.createZkpgsURN("commitment.tildem_0"), tildem_0);

			//      /** TODO refactor with iterator */
			//      if (baseCollection.size() > 1) {
			//        for (BaseRepresentation baseRepresentation : baseCollection.) {
			//          baseMap.put(
			//              URN.createZkpgsURN("commitment.R_i_" + baseRepresentation.getBaseIndex()),
			//              baseRepresentation.getBase());
			//          exponentsMap.put(
			//              URN.createZkpgsURN("commitment.m_i_" + baseRepresentation.getBaseIndex()),
			//              baseRepresentation.getExponent());
			//        }
			//      }

			baseMap.put(URN.createZkpgsURN("commitment.S"), baseS);
			exponentsMap.put(URN.createZkpgsURN("commitments.tildevPrime"), tildevPrime);

			GroupElement sMulti = baseS.modPow(tildevPrime);
			GroupElement tildeU = sMulti.multiply(R_0.modPow(tildem_0));

			//      String tildeUURN = URNType.buildURNComponent(URNType.TILDEU, CommitmentProver.class);
			//      witnesses.put(URN.createZkpgsURN(tildeUURN), tildeU);
			//
			//      gslog.info("witness U: " + tildeU);

			return tildeU;
		} else {

			/** TODO retrieve witness randomness of committed messages from the common store */
			//      String tildem_iURN = POSSESSIONPROVER_WITNESSES_RANDOMNESS_TILDEM; // +
			// base.getBaseIndex();
			//      Map<URN, BigInteger> witnesses = (Map<URN, BigInteger>)
			// proofStore.retrieve(tildem_iURN);

			String tildem_iURN = URNType.buildURNComponent(URNType.TILDEMI, PossessionProver.class, index);
			BigInteger tildem_i = (BigInteger) proofStore.retrieve(tildem_iURN);
			GroupElement baseR = signerPublicKey.getBaseR();
			GroupElement tildeC_i = baseR.modPow(tildem_i).multiply(baseS.modPow(tilder_i));

			//      baseMap.put(URN.createZkpgsURN("commitment.base.R_" + vertex.getBaseIndex()), R_i);
			//      exponentsMap.put(
			//          URN.createZkpgsURN("commitment.exponent.m_" + vertex.getBaseIndex()), tildem_i);

			//      witnesses = new HashMap<URN, GroupElement>();
			//      String tildeC_iURN = URNType.buildURNComponent(URNType.TILDEU,
			// CommitmentProver.class);
			//      witnesses.put(URN.createZkpgsURN(tildeC_iURN), tildeC_i);
			return tildeC_i;
		}
	}

	public BigInteger computeChallenge() {
		return CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
	}

	/**
	 * Post challenge phase computes responses.
	 *
	 * @param cChallenge the common challenge c
	 * @return the map outputs responses
	 */
	@Override
	public Map<URN, BigInteger> executePostChallengePhase(BigInteger cChallenge)
			throws ProofStoreException {

		this.cChallenge = cChallenge;

		if (this.proofStage == STAGE.ISSUING) {
			try {
				computeResponsesIssuing();
			} catch (Exception e) {
				gslog.log(Level.SEVERE, e.getMessage());
			}

		} else if (this.proofStage == STAGE.PROVING) {
			try {
				return computeResponsesProving();
			} catch (Exception e) {
				gslog.log(Level.SEVERE, e.getMessage());
			}
		}

		return responses;
	}

	private void computeResponsesIssuing() throws Exception {

		BigInteger vPrime = (BigInteger) proofStore.retrieve("issuing.recipient.vPrime");

		BigInteger m_0 = (BigInteger) proofStore.retrieve("bases.exponent.m_0");

		BigInteger hatvPrime = tildevPrime.add(cChallenge.multiply(vPrime));
		BigInteger hatm_0 = tildem_0.add(cChallenge.multiply(m_0));
		String hatvPrimeURN = URNType.buildURNComponent(URNType.HATVPRIME, CommitmentProver.class);
		String hatm_0URN = URNType.buildURNComponent(URNType.HATM0, CommitmentProver.class, 0);
		String cChallengeURN = "issuing.commitmentprover.commitment.C";

		responses.put(URN.createZkpgsURN(hatvPrimeURN), hatvPrime);
		responses.put(URN.createZkpgsURN(hatm_0URN), hatm_0);
		proofStore.store(hatvPrimeURN, hatvPrime);
		proofStore.store(hatm_0URN, hatm_0);
		proofStore.store(cChallengeURN, cChallenge);

		if (baseCollection.size() > 0) {
			// TODO The other collection checked against 1!

			BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
			for (BaseRepresentation base : vertexIterator) {
				BigInteger tildem_i =
						(BigInteger)
						proofStore.retrieve(
								URNType.buildURNComponent(
										URNType.TILDEMI, PossessionProver.class, base.getBaseIndex()));
				BigInteger hatm_i = tildem_i.add(cChallenge.multiply(base.getExponent()));
				String hatm_iURN = "issuing.commitmentprover.responses.hatm_i_" + base.getBaseIndex();
				responses.put(URN.createZkpgsURN(hatm_iURN), hatm_i);

				proofStore.store(hatm_iURN, base);
			}

			BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
			for (BaseRepresentation base : edgeIterator) {
				BigInteger tildem_i_j =
						(BigInteger)
						proofStore.retrieve(
								URNType.buildURNComponent(
										URNType.TILDEMIJ, PossessionProver.class, base.getBaseIndex()));
				BigInteger hatm_i_j = tildem_i_j.add(cChallenge.multiply(base.getExponent()));
				String hatm_i_jURN =
						URNType.buildURNComponent(URNType.HATMIJ, CommitmentProver.class, base.getBaseIndex());
				responses.put(URN.createZkpgsURN(hatm_i_jURN), hatm_i_j);
				proofStore.store(hatm_i_jURN, base);
			}
		}
	}

	/**
	 * Compute responses proving.
	 *
	 * @throws Exception the exception
	 */
	public Map<URN, BigInteger> computeResponsesProving() throws Exception {
		String tilder_iURN = getProverURN(URNType.TILDERI, index);
		BigInteger tilder_i = (BigInteger) proofStore.retrieve(tilder_iURN);

		String C_iURN = "prover.commitments.C_" + this.index;
		Map<URN, GSCommitment> commitmentMap =
				(Map<URN, GSCommitment>) proofStore.retrieve("prover.commitments");
		GSCommitment C_i = commitmentMap.get(URN.createZkpgsURN(C_iURN));
		BigInteger r_i = C_i.getRandomness();

		BigInteger hatr_i = tilder_i.add(this.cChallenge.multiply(r_i));

		String hatr_iURN = getProverURN(URNType.HATRI, index);

		responses.put(URN.createZkpgsURN(hatr_iURN), hatr_i);
		gslog.info("store hatr_i " + hatr_i);
		proofStore.store(hatr_iURN, hatr_i);
		return responses;
	}

	public String getProverURN(URNType t) {
		if (URNType.isEnumerable(t)) {
			throw new RuntimeException(
					"URNType " + t + " is enumerable and should be evaluated with an index.");
		}
		return CommitmentProver.URNID + "." + URNType.getClass(t) + "." + URNType.getSuffix(t);
	}

	public String getProverURN(URNType t, int index) {
		if (!URNType.isEnumerable(t)) {
			throw new RuntimeException(
					"URNType " + t + " is not enumerable and should not be evaluated with an index.");
		}
		return CommitmentProver.URNID + "." + URNType.getClass(t) + "." + URNType.getSuffix(t) + index;
	}

	@Override
	public boolean verify() {
		return false;
	}

	@Override
	public List<URN> getGovernedURNs() {
		throw new NotImplementedException("Part of the new prover interface not implemented, yet.");
	}
}
