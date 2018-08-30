package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.EnumeratedURNType;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PossessionProver implements IProver {
	public static final String URNID = "possessionprover";

	private Logger log = GSLoggerConfiguration.getGSlog();

	private final GSSignature blindedSignature;
	private final ExtendedPublicKey extendedPublicKey;
	private BigInteger tildem_0;
	private BigInteger tildevPrime;
	private final ProofStore<Object> proofStore;
	private final KeyGenParameters keyGenParameters;
	private GroupElement tildeZ;
	private BigInteger tildee;
	private Vector<BaseRepresentation> graphResponses = new Vector<BaseRepresentation>();
	private BigInteger tildem_i;
	private BigInteger tildem_i_j;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private BigInteger c;

	private final BaseCollection baseCollection;

	private GroupElement baseS;
	private GroupElement baseR_0;

	private BigInteger hate;
	private BigInteger hatvPrime;
	private BigInteger hatm_0;

	private List<URNType> urnTypes;
	private List<EnumeratedURNType> enumeratedTypes;
	private List<URN> governedURNs;

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
		this.baseCollection = epk.getBaseCollection();
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
		Assert.notNull(baseCollection, "encoded bases collection must not be null");
		Assert.notNull(keyGenParameters, "keygen parameters must not be null");

		this.baseS = extendedPublicKey.getPublicKey().getBaseS();
		this.baseR_0 = extendedPublicKey.getPublicKey().getBaseR_0();

		createWitnessRandomness();
		return computetildeZ();
	}

	/**
	 * The function creates the witness randomness (tilde values) and stores that
	 * randomness in the ProofStore.
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
			tildem_i = CryptoUtilsFacade.computeRandomNumber(messageLength);
			proofStore.store(getProverURN(URNType.TILDEMI, base.getBaseIndex()), tildem_i);
		}

		// Edge Messages
		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation base : edgeIterator) {
			tildem_i_j = CryptoUtilsFacade.computeRandomNumber(messageLength);
			proofStore.store(getProverURN(URNType.TILDEMIJ, base.getBaseIndex()), tildem_i_j);
		}
	}


	private GroupElement computetildeZ() {
		Assert.notNull(tildee, "TildeE must not be null.");
		Assert.notNull(tildevPrime, "tildevPrime must not be null.");

		// gslog.info("aPrime: " + blindedSignature.getA());
		GroupElement aPrimeEtilde = blindedSignature.getA().modPow(tildee);

		GroupElement sTildeVPrime = baseS.modPow(tildevPrime);
		GroupElement baseProduct = extendedPublicKey.getPublicKey().getQRGroup().getOne();

		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation baseRepresentation : vertexIterator) {
			BigInteger vertexWitness = (BigInteger) proofStore.retrieve(
					URNType.buildURNComponent(URNType.TILDEMI, this.getClass(), baseRepresentation.getBaseIndex()));
			baseProduct = baseProduct.multiply(baseRepresentation.getBase().modPow(vertexWitness));
		}

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation baseRepresentation : edgeIterator) {
			BigInteger edgeWitness = (BigInteger) proofStore.retrieve(
					URNType.buildURNComponent(URNType.TILDEMIJ, this.getClass(), baseRepresentation.getBaseIndex()));

			baseProduct = baseProduct.multiply(baseRepresentation.getBase().modPow(edgeWitness));
		}

		tildem_0 = (BigInteger) proofStore.retrieve(getProverURN(URNType.TILDEM0));

		GroupElement baseR_0tildem_0 = baseR_0.modPow(tildem_0);

		tildeZ = aPrimeEtilde.multiply(sTildeVPrime).multiply(baseR_0tildem_0).multiply(baseProduct);

		return tildeZ;
	}

	public BigInteger computeChallenge() {
		return CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
	}

	@Override
	public Map<URN, BigInteger> executePostChallengePhase(BigInteger cChallenge)
			throws ProofStoreException {

		// gslog.info("prover: post challenge phase");
		this.c = cChallenge;

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

		BigInteger m_0 = (BigInteger) proofStore.retrieve("bases.exponent.m_0");

		BigInteger m_i;
		BigInteger hatm_i;
		String hatm_iURN;

		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation vertexBase : vertexIterator) {
			int baseIndex = vertexBase.getBaseIndex();
			m_i = vertexBase.getExponent();
			tildem_i = (BigInteger) proofStore.retrieve(getProverURN(URNType.TILDEMI, baseIndex));
			hatm_i = tildem_i.add(this.c.multiply(m_i));

			BaseRepresentation vertexResponse = vertexBase.clone();
			vertexResponse.setExponent(hatm_i);
			graphResponses.addElement(vertexResponse);

			hatm_iURN = getProverURN(URNType.HATMI, baseIndex);

			responses.put(URN.createZkpgsURN(hatm_iURN), hatm_i);

			try {
				proofStore.store(hatm_iURN, hatm_i);
			} catch (Exception e) {
				gslog.log(Level.SEVERE, e.getMessage());
			}
		}

		BigInteger m_i_j;
		BigInteger hatm_i_j;
		String hatm_i_jURN;

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation edgeBase : edgeIterator) {
			int baseIndex = edgeBase.getBaseIndex();
			m_i_j = edgeBase.getExponent();
			tildem_i_j = (BigInteger) proofStore.retrieve(getProverURN(URNType.TILDEMIJ, baseIndex));

			hatm_i_j = tildem_i_j.add(this.c.multiply(m_i_j));

			BaseRepresentation edgeResponse = edgeBase.clone();
			edgeResponse.setExponent(hatm_i_j);
			graphResponses.addElement(edgeResponse);

			hatm_i_jURN = getProverURN(URNType.HATMIJ, baseIndex);

			responses.put(URN.createZkpgsURN(hatm_i_jURN), hatm_i_j);

			try {
				proofStore.store(hatm_i_jURN, hatm_i_j);
			} catch (Exception e) {
				gslog.log(Level.SEVERE, e.getMessage());
			}
		}
		//		gslog.info("tildee bitlength: " + tildee.bitLength());
		//		gslog.info("c bitlength: " + c.bitLength());

		hate = tildee.add(this.c.multiply(ePrime));
		hatvPrime = tildevPrime.add(this.c.multiply(vPrime));
		hatm_0 = tildem_0.add(this.c.multiply(m_0));

		String hateURN = getProverURN(URNType.HATE);
		String hatvPrimeURN = getProverURN(URNType.HATVPRIME);
		String hatm_0URN = getProverURN(URNType.HATM0);

		responses.put(URN.createZkpgsURN(hateURN), hate);
		responses.put(URN.createZkpgsURN(hatvPrimeURN), hatvPrime);
		responses.put(URN.createZkpgsURN(hatm_0URN), hatm_0);


		proofStore.store(hateURN, hate);
		proofStore.store(hatvPrimeURN, hatvPrime);
		proofStore.store(hatm_0URN, hatm_0);


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
		if (this.c == null) return false;
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
				.modPow(c.negate());

		// Establish the initial product to integrate the graph elements subsequently
		GroupElement verifier =
				baseZnegC.multiply(aPrimeHatE).multiply(baseSHatVPrime).multiply(baseR_0HatM_0);

		// Iterate over the graph components as recorded by the PossessionProver
		Iterator<BaseRepresentation> graphResponseIterator = graphResponses.iterator();
		while (graphResponseIterator.hasNext()) {
			BaseRepresentation baseRepresentation = (BaseRepresentation) graphResponseIterator.next();
			// log.info(" Treating graph element " + baseRepresentation);
			verifier =
					verifier.multiply(baseRepresentation.getBase().modPow(baseRepresentation.getExponent()));
		}

		// The result must be equal to the witness tildeZ.
		return verifier.equals(this.tildeZ);
	}

	public String getProverURN(URNType t) {
		if (URNType.isEnumerable(t)) {
			throw new RuntimeException(
					"URNType " + t + " is enumerable and should be evaluated with an index.");
		}
		return PossessionProver.URNID + "." + URNType.getClass(t) + "." + URNType.getSuffix(t);
	}

	public String getProverURN(URNType t, int index) {
		if (!URNType.isEnumerable(t)) {
			throw new RuntimeException(
					"URNType " + t + " is not enumerable and should not be evaluated with an index.");
		}
		return PossessionProver.URNID + "." + URNType.getClass(t) + "." + URNType.getSuffix(t) + index;
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
			int vertexIndex = 1;
			for (@SuppressWarnings("unused") BaseRepresentation baseRepresentation : vertexIterator) {
				enumeratedTypes.add(new EnumeratedURNType(URNType.TILDEMI, vertexIndex++));
			}
			BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
			int edgeIndex = 1;
			for (@SuppressWarnings("unused") BaseRepresentation baseRepresentation : edgeIterator) {
				enumeratedTypes.add(new EnumeratedURNType(URNType.TILDEMI, edgeIndex++));
			}
		}

		if (governedURNs == null) {
			governedURNs = Collections.unmodifiableList(URNType.buildURNList(urnTypes, this.getClass()));
		}
		return governedURNs;
	}
}
