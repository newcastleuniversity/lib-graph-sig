package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.EnumeratedURNType;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A PossessionProver is responsible for proving the possession of a graph signature and its
 * corresponding secrets.
 *
 * <p>The PossessionProver expects the graph signature to be blinded by a ProverOrchestrator. To
 * preserve multi-use unlinkability, hence, GSSignature.blind() must be called before the proof is
 * executed.
 */
public class PossessionProver implements IProver {
	public static final String URNID = "possessionprover";

	//private Logger log = GSLoggerConfiguration.getGSlog();

	private final GSSignature blindedSignature;
	private final ExtendedPublicKey extendedPublicKey;
	private BigInteger tildem_0;
	private BigInteger tildevPrime;
	private final ProofStore<Object> proofStore;
	private final KeyGenParameters keyGenParameters;
	private GroupElement tildeZ;
	private BigInteger tildee;
	private Vector<BaseRepresentation> graphResponses = new Vector<BaseRepresentation>();
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private BigInteger cChallenge;

	private final BaseCollection baseCollection;

	private final GroupElement baseS;
	private final GroupElement baseR_0;

	private BigInteger hate;
	private BigInteger hatvPrime;
	private BigInteger hatm_0;

	private transient List<URNType> urnTypes;
	private transient List<EnumeratedURNType> enumeratedTypes;
	private transient List<URN> governedURNs;

	/**
	 * Constructs a new PossessionProver for a given GSSignature.
	 *
	 * <p>For unlinkability, it is required that the GSSignature is blinded by a calling
	 * ProofOrchestrator.
	 *
	 * @param blindedSignature already blinded GSSignature to prove possession of.
	 * @param epk ExtendedPublicKey for the signature's issuer.
	 * @param ps ProofStore to be used for this proof.
	 */
	// TODO Refactor to dual indexing for edges.
	public PossessionProver(
			final GSSignature blindedSignature,
			final ExtendedPublicKey epk,
			final ProofStore<Object> ps) {
		Assert.notNull(blindedSignature, "blinded graph signature must not be null");
		Assert.notNull(epk, "extended public key must not be null");
		Assert.notNull(ps, "Proof store must not be null");

		this.extendedPublicKey = epk;
		this.proofStore = ps;
		this.blindedSignature = blindedSignature;
		this.keyGenParameters = epk.getKeyGenParameters();
		this.baseCollection = blindedSignature.getEncodedBases();
		this.baseR_0 = epk.getPublicKey().getBaseR_0();
		this.baseS = epk.getPublicKey().getBaseS();
	}

	@Override
	public void executePrecomputation() {
		// NO PRE-COMPUTATION IS NEEDED: NO-OP.
	}

	@Override
	public Map<URN, GroupElement> executeCompoundPreChallengePhase() throws ProofStoreException {
		GroupElement witness = executePreChallengePhase();
		Map<URN, GroupElement> witnesses = new HashMap<>();
		witnesses.put(URN.createZkpgsURN(getProverURN(URNType.TILDEZ)), witness);
		return witnesses;
	}

	@Override
	public GroupElement executePreChallengePhase() throws ProofStoreException {
		Assert.notNull(baseCollection, "Encoded bases collection must not be null");
		Assert.notNull(keyGenParameters, "Keygen parameters must not be null");

		createWitnessRandomness();
		return computetildeZ();
	}

	/**
	 * The function creates the witness randomness (tilde values) and stores that randomness in the
	 * ProofStore.
	 *
	 * @throws ProofStoreException if the values could not be written to the ProofStore.
	 */
	private void createWitnessRandomness() throws ProofStoreException {

		// Signing exponent e
		int tildeeLength = keyGenParameters.getL_prime_e() + keyGenParameters.getProofOffset();
		tildee = CryptoUtilsFacade.computeRandomNumber(tildeeLength);
		proofStore.store(getProverURN(URNType.TILDEE), tildee);

		// Blinding randomness v'
		int tildevLength = keyGenParameters.getL_v() + keyGenParameters.getProofOffset();
		tildevPrime = CryptoUtilsFacade.computeRandomNumber(tildevLength);
		proofStore.store(getProverURN(URNType.TILDEVPRIME), tildevPrime);

		// Message witness for m_0
		int messageLength = keyGenParameters.getL_m() + keyGenParameters.getProofOffset();
		tildem_0 = CryptoUtilsFacade.computeRandomNumber(messageLength);
		proofStore.store(getProverURN(URNType.TILDEM0), tildem_0);

		// Vertex Messages
		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation base : vertexIterator) {
			BigInteger tildem_i = CryptoUtilsFacade.computeRandomNumber(messageLength);
			proofStore.store(getProverURN(URNType.TILDEMI, base.getBaseIndex()), tildem_i);
		}

		// Edge Messages
		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation base : edgeIterator) {
			BigInteger tildem_i_j = CryptoUtilsFacade.computeRandomNumber(messageLength);
			proofStore.store(getProverURN(URNType.TILDEMIJ, base.getBaseIndex()), tildem_i_j);
		}
	}

	private GroupElement computetildeZ() {
		Assert.notNull(tildee, "TildeE must not be null.");
		Assert.notNull(tildevPrime, "tildevPrime must not be null.");

		// gslog.info("aPrime: " + blindedSignature.getA());
		GroupElement aPrimeEtilde = blindedSignature.getA().modPow(tildee);

		GroupElement sTildeVPrime = baseS.modPow(tildevPrime);
		
		tildem_0 = (BigInteger) proofStore.retrieve(getProverURN(URNType.TILDEM0));

		GroupElement baseR_0tildem_0 = baseR_0.modPow(tildem_0);
		
		GroupElement baseProduct = extendedPublicKey.getPublicKey().getQRGroup().getOne();

		Vector<BaseRepresentation> witnessBases = new Vector<BaseRepresentation>();

		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation baseRepresentation : vertexIterator) {
			BigInteger vertexWitness =
					(BigInteger)
					proofStore.retrieve(
							URNType.buildURNComponent(
									URNType.TILDEMI, this.getClass(), baseRepresentation.getBaseIndex()));
			
			// Reporting
			BaseRepresentation tildeBase = baseRepresentation.clone();
			tildeBase.setExponent(vertexWitness);
			witnessBases.add(tildeBase);
			
			baseProduct = baseProduct.multiply(baseRepresentation.getBase().modPow(vertexWitness));
		}

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation baseRepresentation : edgeIterator) {
			BigInteger edgeWitness =
					(BigInteger)
					proofStore.retrieve(
							URNType.buildURNComponent(
									URNType.TILDEMIJ, this.getClass(), baseRepresentation.getBaseIndex()));

			// Reporting
			BaseRepresentation tildeBase = baseRepresentation.clone();
			tildeBase.setExponent(edgeWitness);
			witnessBases.add(tildeBase);

			baseProduct = baseProduct.multiply(baseRepresentation.getBase().modPow(edgeWitness));
		}

//		log.log(
//				Level.INFO,
//				"||TildeZ Graph: "
//						+ GraphUtils.iteratedGraphToExpString(witnessBases.iterator(), proofStore));

		tildeZ = aPrimeEtilde.multiply(sTildeVPrime).multiply(baseR_0tildem_0).multiply(baseProduct);

		return tildeZ;
	}

	public BigInteger computeChallenge() {
		return CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
	}

	@Override
	public Map<URN, BigInteger> executePostChallengePhase(BigInteger cChallenge)
			throws ProofStoreException {
		Assert.notNull(cChallenge, "The challenge must not be null.");

		// gslog.info("prover: post challenge phase");
		this.cChallenge = cChallenge;

		Map<URN, BigInteger> responses = new HashMap<URN, BigInteger>();

		// More reliable to use the GSSignature stored in the state of the class.
		//    String ePrimeURN = "prover.blindedgs.ePrime";
		//    BigInteger ePrime = (BigInteger) proverStore.retrieve(ePrimeURN);
		//    gslog.info("e prime bitlength: " + ePrime.bitLength());
		//
		//    String vPrimeURN = "prover.blindedgs.vPrime";
		//    BigInteger vPrime = (BigInteger) proverStore.retrieve(vPrimeURN);
		BigInteger ePrime = blindedSignature.getEPrime();
		BigInteger vPrime = blindedSignature.getV();

		
		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation vertexBase : vertexIterator) {
			int baseIndex = vertexBase.getBaseIndex();
			BigInteger m_i = vertexBase.getExponent();
			BigInteger tildem_i =
					(BigInteger) proofStore.retrieve(getProverURN(URNType.TILDEMI, baseIndex));
			BigInteger hatm_i = tildem_i.add(this.cChallenge.multiply(m_i));

			// Reporting
			BaseRepresentation vertexResponse = vertexBase.clone();
			vertexResponse.setExponent(hatm_i);
			graphResponses.addElement(vertexResponse);

			String hatm_iURN = getProverURN(URNType.HATMI, baseIndex);

			responses.put(URN.createZkpgsURN(hatm_iURN), hatm_i);

			proofStore.store(hatm_iURN, hatm_i);
		}

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation edgeBase : edgeIterator) {
			int baseIndex = edgeBase.getBaseIndex();
			BigInteger m_i_j = edgeBase.getExponent();
			BigInteger tildem_i_j =
					(BigInteger) proofStore.retrieve(getProverURN(URNType.TILDEMIJ, baseIndex));

			BigInteger hatm_i_j = tildem_i_j.add(this.cChallenge.multiply(m_i_j));

			BaseRepresentation edgeResponse = edgeBase.clone();
			edgeResponse.setExponent(hatm_i_j);
			graphResponses.addElement(edgeResponse);

			String hatm_i_jURN = getProverURN(URNType.HATMIJ, baseIndex);

			responses.put(URN.createZkpgsURN(hatm_i_jURN), hatm_i_j);

			proofStore.store(hatm_i_jURN, hatm_i_j);
		}
		
		boolean completedBase0 = false;
		BaseIterator base0Iterator = baseCollection.createIterator(BASE.BASE0);
		for (BaseRepresentation base0Base : base0Iterator) {
			// Testing that the base R_0 is only gone through once.
			if (completedBase0) throw new IllegalStateException("The Base R_0 responsible for "
					+ "encoding the master secret key msk should only be included once on a signature.");
			completedBase0 = true;
			
			BigInteger m_0 = (BigInteger) base0Base.getExponent();
			BigInteger tildem_0 =
					(BigInteger) proofStore.retrieve(getProverURN(URNType.TILDEM0));
			Assert.notNull(tildem_0 , "TildeM_0 could not be retrieved.");
			
			hatm_0 = tildem_0.add(this.cChallenge.multiply(m_0));
			
			proofStore.save(URNType.buildURN(URNType.HATM0, this.getClass()), hatm_0);
			responses.put(URNType.buildURN(URNType.HATM0, this.getClass()), hatm_0);
		}

//		log.log(
//				Level.INFO,
//				"||hatZ Graph: "
//						+ GraphUtils.iteratedGraphToExpString(graphResponses.iterator(), proofStore));

		hate = tildee.add(this.cChallenge.multiply(ePrime));
		hatvPrime = tildevPrime.add(this.cChallenge.multiply(vPrime));

		String hateURN = getProverURN(URNType.HATE);
		String hatvPrimeURN = getProverURN(URNType.HATVPRIME);

		responses.put(URN.createZkpgsURN(hateURN), hate);
		responses.put(URN.createZkpgsURN(hatvPrimeURN), hatvPrime);

		proofStore.store(hateURN, hate);
		proofStore.store(hatvPrimeURN, hatvPrime);

		return responses;
	}

	/**
	 * Self-verifies the proof responses of the PossessionProver.
	 *
	 * <p>It is required that the bases raised to the responses multiplied by base Z to the negated
	 * challenge yields the witness tildeZ.
	 *
	 * @return <tt>true</tt> if the response values are computed correctly. If verify() is called
	 *     before the challenge is submitted, the method always returns <tt>false</tt>.
	 */
	@Override
	public boolean verify() {
		if (this.cChallenge == null || this.tildeZ == null) return false;
		// This verification uses the verification equation of the TOPOCERT GSPossessionVerifier
		// Modified with the correctness proof of the corresponding proof, that is,
		// The equation must be equal to tildeZ.

		// Establish the non-graph elements of the signature
		GroupElement aPrimeHatE = blindedSignature.getA().modPow(hate);
		GroupElement baseSHatVPrime = baseS.modPow(hatvPrime);
		GroupElement baseR_0HatM_0 = baseR_0.modPow(hatm_0);

		// Compensate for the offset of e'
		BigInteger offsetExp = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_e() - 1);
		GroupElement aPrimeOffset = (blindedSignature.getA().modPow(offsetExp)).modInverse();

		// Cancel out the challenge c
		GroupElement baseZnegC =
				(this.extendedPublicKey.getPublicKey().getBaseZ().multiply(aPrimeOffset))
				.modPow(cChallenge.negate());

		// Establish the initial product to integrate the graph elements subsequently
		GroupElement verifier =
				baseZnegC.multiply(aPrimeHatE).multiply(baseSHatVPrime).multiply(baseR_0HatM_0);

		// Iterate over the graph components as recorded by the PossessionProver
//		log.log(
//				Level.INFO,
//				"||Self-Verify Graph: "
//						+ GraphUtils.iteratedGraphToExpString(graphResponses.iterator(), proofStore));

		for (BaseRepresentation baseRepresentation : graphResponses) {
//			log.info("Including base " + GraphUtils.graphTypeToString(baseRepresentation)
//			+ baseRepresentation.getBaseIndex() + " with exponent "
//			+ GraphUtils.expKeyToString(baseRepresentation, proofStore) 
//			+ " = " + baseRepresentation.getExponent());
			verifier =
					verifier.multiply(baseRepresentation.getBase().modPow(baseRepresentation.getExponent()));
		}

		// The result must be equal to the witness tildeZ.
		return verifier.equals(this.tildeZ);
	}

	public String getProverURN(URNType t) {
		if (URNType.isEnumerable(t)) {
			throw new IllegalArgumentException(
					"URNType " + t + " is enumerable and should be evaluated with an index.");
		}
		return PossessionProver.URNID + "." + URNType.getNameSpaceComponentClass(t) + "." + URNType.getSuffix(t);
	}

	public String getProverURN(URNType t, int index) {
		if (!URNType.isEnumerable(t)) {
			throw new IllegalArgumentException(
					"URNType " + t + " is not enumerable and should not be evaluated with an index.");
		}
		return PossessionProver.URNID + "." + URNType.getNameSpaceComponentClass(t) + "." + URNType.getSuffix(t) + index;
	}

	@Override
	public List<URN> getGovernedURNs() {
		if (urnTypes == null) {
			urnTypes =
					Collections.unmodifiableList(
							Arrays.asList(
									URNType.TILDEE,
									URNType.TILDEV,
									URNType.TILDEM0,
									URNType.HATE,
									URNType.HATV,
									URNType.HATM0));
		}
		if (enumeratedTypes == null) {
			enumeratedTypes = new ArrayList<EnumeratedURNType>(baseCollection.size());
			BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
			for (BaseRepresentation base : vertexIterator) {
				enumeratedTypes.add(new EnumeratedURNType(URNType.TILDEMI, base.getBaseIndex()));
			}
			BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
			for (BaseRepresentation base : edgeIterator) {
				enumeratedTypes.add(new EnumeratedURNType(URNType.TILDEMIJ, base.getBaseIndex()));
			}
		}

		if (governedURNs == null) {
			governedURNs = Collections.unmodifiableList(URNType.buildURNList(urnTypes, this.getClass()));
		}
		return governedURNs;
	}
}
