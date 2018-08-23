package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
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
import java.security.NoSuchAlgorithmException;
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

	private GSSignature blindedSignature;
	private ExtendedPublicKey extendedPublicKey;
	private BigInteger R_0;
	private BigInteger tildem_0;
	private BigInteger tildevPrime;
	private ProofStore<Object> proofStore;
	private KeyGenParameters keyGenParameters;
	private GroupElement tildeZ;
	private BigInteger tildee;
	private Vector<BaseRepresentation> graphResponses = new Vector<BaseRepresentation>();
	private BigInteger tildem_i;
	private BigInteger tildem_i_j;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private BigInteger c;
	private int baseIndex;
	private BaseCollection baseCollection;

	private GroupElement baseS;
	private GroupElement baseR_0;

	private BigInteger hate;
	private BigInteger hatvPrime;
	private BigInteger hatm_0;
	
	private List<URNType> urnTypes;
	private List<EnumeratedURNType> enumeratedTypes;
	private List<URN> governedURNs;
	
	PossessionProver() {};

	/**
	 * Constructs a new PossessionProver for a given GSSignature.
	 * 
	 * <p>For unlinkability, it is required that the GSSignature is blinded by a calling ProofOrchestrator.
	 * 
	 * @param blindedSignature already blinded GSSignature to prove possession of.
	 * @param epk ExtendedPublicKey for the signature's issuer.
	 * @param ps ProofStore to be used for this proof.
	 */
	// TODO Make dependencies final. Then remove auxiliary parameters from preChallengePhase();
	// TODO Refactor to dual indexing for edges.
	public PossessionProver(GSSignature blindedSignature, ExtendedPublicKey epk, ProofStore<Object> ps) {
		super();
		
		this.extendedPublicKey = epk;
		this.proofStore = ps;
		this.blindedSignature = blindedSignature;
	}

	@Override
	public void executePrecomputation() {
		// NO PRE-COMPUTATION IS NEEDED: NO-OP.
	}

	public GroupElement executePreChallengePhase() throws ProofStoreException {
		Assert.notNull(blindedSignature, "blinded graph signature must not be null");
		Assert.notNull(extendedPublicKey, "extended public key must not be null");
		Assert.notNull(baseCollection, "encoded bases collection must not be null");
		Assert.notNull(proofStore, "prover store must not be null");
		Assert.notNull(keyGenParameters, "keygen parameters must not be null");

		
		this.baseS = extendedPublicKey.getPublicKey().getBaseS();
		this.baseR_0 = extendedPublicKey.getPublicKey().getBaseR_0();

		try {
			createWitnessRandomness();
			storeWitnessRandomness();
		} catch (Exception e) {
			gslog.log(Level.SEVERE, e.getMessage());
		}

		return computetildeZ();
	}

	private void createWitnessRandomness() throws ProofStoreException {

		int tildeeLength =
				keyGenParameters.getL_prime_e()
				+ keyGenParameters.getL_statzk()
				+ keyGenParameters.getL_H()
				+ 1;
		tildee = CryptoUtilsFacade.computeRandomNumber(tildeeLength);

		int tildevLength =
				keyGenParameters.getL_v() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;
		tildevPrime = CryptoUtilsFacade.computeRandomNumber(tildevLength);

		int messageLength =
				keyGenParameters.getL_m() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;

		tildem_0 = CryptoUtilsFacade.computeRandomNumber(messageLength);

		//    vertexWitnesses = new LinkedHashMap<>();
		//    edgeWitnesses = new LinkedHashMap<>();
		String witnessRandomnessURN = "";
		
		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation base : vertexIterator) {
			tildem_i = CryptoUtilsFacade.computeRandomNumber(messageLength);
			witnessRandomnessURN =
					"possessionprover.witnesses.randomness.vertex.tildem_i_" + base.getBaseIndex();
			//      vertexWitnesses.put(URN.createZkpgsURN(witnessRandomnessURN), tildem_i);
			proofStore.store(witnessRandomnessURN, tildem_i);
		}

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation base : edgeIterator) {
			tildem_i_j = CryptoUtilsFacade.computeRandomNumber(messageLength);
			witnessRandomnessURN =
					"possessionprover.witnesses.randomness.edge.tildem_i_j_" + base.getBaseIndex();
			//      edgeWitnesses.put(URN.createZkpgsURN(witnessRandomnessURN), tildem_i_j);
			proofStore.store(witnessRandomnessURN, tildem_i_j);
		}
	}

	private void storeWitnessRandomness() throws Exception {
		String tildeeURN = "possessionprover.witnesses.randomness.tildee";
		proofStore.store(tildeeURN, tildee);

		String tildevURN = "possessionprover.witnesses.randomness.tildevprime";
		proofStore.store(tildevURN, tildevPrime);

		String tildem_0URN = "possessionprover.witnesses.randomness.tildem_0";
		proofStore.store(tildem_0URN, tildem_0);

		//    String tildem_iURN = "possessionprover.witnesses.randomness.tildem_i";
		//    proverStore.store(tildem_iURN, vertexWitnesses);
		//
		//    String tildem_i_jURN = "possessionprover.witnesses.randomness.tildem_i_j";
		//    proverStore.store(tildem_i_jURN, edgeWitnesses);
	}

	private GroupElement computeWitness() {
		return computetildeZ();
	}

	private GroupElement computetildeZ() {
		Assert.notNull(tildee, "TildeE must not be null.");
		Assert.notNull(tildevPrime, "tildevPrime must not be null.");

		//gslog.info("aPrime: " + blindedSignature.getA());
		GroupElement aPrimeEtilde = blindedSignature.getA().modPow(tildee);

		//gslog.info("ePrime + 2^le-1: " + blindedSignature.getEPrime().add(NumberConstants.TWO.getValue().pow(keyGenParameters.getL_e()-1)));


		GroupElement sTildeVPrime = baseS.modPow(tildevPrime);
		GroupElement baseProduct = extendedPublicKey.getPublicKey().getQRGroup().getOne();

		String tildemURN;
		BigInteger vertexWitness;
		BigInteger edgeWitness;

		//    for (BaseRepresentation baseRepresentation : vertexIterator) {
		//      tildemURN =
		//          "possessionprover.witnesses.randomness.vertex.tildem_i_"
		//              + baseRepresentation.getBaseIndex();
		//      vertexWitness = (BigInteger) proverStore.retrieve(tildemURN);
		//      //      vertexWitness = vertexWitnesses.get(URN.createZkpgsURN(baseURN));
		//      baseProduct = baseProduct.multiply(baseRepresentation.getBase().modPow(vertexWitness));
		//    }
		//
		//    for (BaseRepresentation baseRepresentation : edgeIterator) {
		//      tildemURN =
		//          "possessionprover.witnesses.randomness.edge.tildem_i_j_"
		//              + baseRepresentation.getBaseIndex();
		//      //      edgeWitness = edgeWitnesses.get(URN.createZkpgsURN(baseURN));
		//      edgeWitness = (BigInteger) proverStore.retrieve(tildemURN);
		//      baseProduct = baseProduct.multiply(baseRepresentation.getBase().modPow(edgeWitness));
		//    }

		String tildem_0URN = "possessionprover.witnesses.randomness.tildem_0";
		tildem_0 = (BigInteger) proofStore.retrieve(tildem_0URN);

		//gslog.info("aPrimeEtilde bitlength: " + aPrimeEtilde.bitLength());
		GroupElement baseR_0tildem_0 = baseR_0.modPow(tildem_0);
		tildeZ = aPrimeEtilde.multiply(sTildeVPrime).multiply(baseR_0tildem_0);

		//gslog.info("tildeZ: " + tildeZ);
		//gslog.info("tildeZ bitlength: " + tildeZ.bitLength());
		return tildeZ;
	}

	public BigInteger computeChallenge() throws NoSuchAlgorithmException {
		return CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
	}

	private void setChallenge(BigInteger challenge) {
		this.c = challenge;
	}

	public Map<URN, BigInteger> executePostChallengePhase(BigInteger cChallenge) throws ProofStoreException {
		
		//gslog.info("prover: post challenge phase");
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

		BaseIterator baseR0Iterator = baseCollection.createIterator(BASE.BASE0);
		BaseRepresentation baseRepR_0 = checkBaseR_0(baseR0Iterator);

		BigInteger m_0 = baseRepR_0.getExponent();

		BigInteger m_i;
		BigInteger hatm_i;
		String tildem_iURN;
		String tildem_iPath = "possessionprover.witnesses.randomness.vertex.tildem_i_";

		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation vertexBase : vertexIterator) {
			baseIndex = vertexBase.getBaseIndex();
			tildem_iURN = tildem_iPath + baseIndex;
			//      gslog.info("vertex m urn: " + tildem_iURN);
			m_i = vertexBase.getExponent();
			tildem_i = (BigInteger) proofStore.retrieve(tildem_iURN);
			hatm_i = tildem_i.add(this.c.multiply(m_i));

			BaseRepresentation vertexResponse = vertexBase.clone();
			vertexResponse.setExponent(hatm_i);
			graphResponses.addElement(vertexResponse);

			String hatm_iURN = "possessionprover.responses.vertex.hatm_i_" + baseIndex;

			responses.put(URN.createZkpgsURN(hatm_iURN), hatm_i);
			
			try {
				proofStore.store(hatm_iURN, hatm_i);
			} catch (Exception e) {
				gslog.log(Level.SEVERE, e.getMessage());
			}
		}

		BigInteger m_i_j;
		BigInteger hatm_i_j;
		String tildem_i_jURN;
		String tildem_i_jPath = "possessionprover.witnesses.randomness.edge.tildem_i_j_";

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation edgeBase : edgeIterator) {
			baseIndex = edgeBase.getBaseIndex();
			tildem_i_jURN = tildem_i_jPath + baseIndex;
			m_i_j = edgeBase.getExponent();
			tildem_i_j = (BigInteger) proofStore.retrieve(tildem_i_jURN);

			hatm_i_j = tildem_i_j.add(this.c.multiply(m_i_j));

			BaseRepresentation edgeResponse = edgeBase.clone();
			edgeResponse.setExponent(hatm_i_j);
			graphResponses.addElement(edgeResponse);

			String hatm_i_jURN = "possessionprover.responses.edge.hatm_i_j_" + baseIndex;

			responses.put(URN.createZkpgsURN(hatm_i_jURN), hatm_i_j);
			
			try {
				proofStore.store(hatm_i_jURN, hatm_i_j);
			} catch (Exception e) {
				gslog.log(Level.SEVERE, e.getMessage());
			}
		}
		gslog.info("tildee bitlength: " + tildee.bitLength());
		gslog.info("c bitlength: " + c.bitLength());
		
		hate = tildee.add(this.c.multiply(ePrime));
		hatvPrime = tildevPrime.add(this.c.multiply(vPrime));
		hatm_0 = tildem_0.add(this.c.multiply(m_0));

		String hateURN = "possessionprover.responses.hate";
		String hatvPrimeURN = "possessionprover.responses.hatvprime";
		String hatm_0URN = "possessionprover.responses.hatm_0";
		
		responses.put(URN.createZkpgsURN(hateURN), hate);
		responses.put(URN.createZkpgsURN(hatvPrimeURN), hatvPrime);
		responses.put(URN.createZkpgsURN(hatm_0URN), hatm_0);

		try {
			proofStore.store(hateURN, hate);
			proofStore.store(hatvPrimeURN, hatvPrime);
			proofStore.store(hatm_0URN, hatm_0);
		} catch (Exception e) {
			gslog.log(Level.SEVERE, e.getMessage());
		}

		return responses;
		
	}

	private BaseRepresentation checkBaseR_0(BaseIterator baseR0Iterator) {
		BaseRepresentation baseRepR_0;
		if (baseR0Iterator.hasNext()) {
			baseRepR_0 = baseR0Iterator.next();
			if (!baseRepR_0.getBase().equals(baseR_0)) {
				throw new IllegalStateException(
						"base R0 value is not equal to the R0 value of the base iterator");
			}
		} else {
			throw new IllegalStateException("base R0 is not present in base iterator");
		}
		return baseRepR_0;
	}


	public boolean isSetupComplete() {
		return false;
	}

	/**
	 * Self-verifies the proof responses of the PossessionProver.
	 * 
	 * It is required that the bases raised to the responses multiplied by 
	 * base Z to the negated challenge yields the witness tildeZ.
	 * 
	 * @return <tt>true</tt> if the response values are computed correctly.
	 *   If verify() is called before the challenge is submitted, the method always returns <tt>false</tt>.
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
		BigInteger offsetExp = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_e()-1);
		GroupElement aPrimeOffset = (blindedSignature.getA().modPow(offsetExp)).modInverse();

		// Cancel out the challenge c
		GroupElement baseZnegC = (this.extendedPublicKey.getPublicKey().getBaseZ().multiply(aPrimeOffset)).modPow(c.negate());

		// Establish the initial product to integrate the graph elements subsequently
		GroupElement verifier = baseZnegC.multiply(aPrimeHatE).multiply(baseSHatVPrime).multiply(baseR_0HatM_0);

		// Iterate over the graph components as recorded by the PossessionProver
		Iterator<BaseRepresentation> graphResponseIterator = graphResponses.iterator();
		while (graphResponseIterator.hasNext()) {
			BaseRepresentation baseRepresentation = (BaseRepresentation) graphResponseIterator.next();
			// log.info(" Treating graph element " + baseRepresentation);
			verifier = verifier.multiply(baseRepresentation.getBase().modPow(baseRepresentation.getExponent()));
		}

		// The result must be equal to the witness tildeZ.
		return verifier.equals(this.tildeZ);
	}

	public String getProverURN(URNType t) {
		if (URNType.isEnumerable(t)) {
			throw new RuntimeException("URNType " + t + " is enumerable and should be evaluated with an index.");
		}
		return PossessionProver.URNID + "." + URNType.getClass(t) + "." + URNType.getSuffix(t);
	}

	public String getProverURN(URNType t, int index) {
		if (!URNType.isEnumerable(t)) {
			throw new RuntimeException("URNType " + t + " is not enumerable and should not be evaluated with an index.");
		}
		return PossessionProver.URNID + "." + URNType.getClass(t) + "." + URNType.getSuffix(t) + index;
	}

	public List<URN> getGovernedURNs() {
		if (urnTypes == null) {
			urnTypes = Collections.unmodifiableList(
			    Arrays.asList(URNType.TILDEE, URNType.TILDEV, URNType.TILDEM0, URNType.HATE, URNType.HATV, URNType.HATM0));
		}
		if (enumeratedTypes == null) {
			enumeratedTypes = new ArrayList<EnumeratedURNType>(baseCollection.size());
			BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
			int vertexIndex = 1;
			for (BaseRepresentation baseRepresentation : vertexIterator) {
				enumeratedTypes.add(new EnumeratedURNType(URNType.TILDEMI, vertexIndex++));
			}
			BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
			int edgeIndex = 1;
			for (BaseRepresentation baseRepresentation : vertexIterator) {
				enumeratedTypes.add(new EnumeratedURNType(URNType.TILDEMI, edgeIndex++));
			}
		}
		
		if (governedURNs == null) {
			governedURNs = Collections.unmodifiableList(URNType.buildURNList(urnTypes, this.getClass()));
		}
		return governedURNs;
	}
}
