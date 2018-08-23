package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.orchestrator.IProverOrchestrator;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElementPQ;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/** The type Group setup prover. */
public class GroupSetupProver implements IProver {

	public static final String URNID = "groupsetupprover";

	private final ExtendedKeyPair extendedKeyPair;
	private ExtendedPublicKey ePublicKey;
	private BigInteger r_Z;
	private BigInteger r;
	private BigInteger r_0;
	private BigInteger tilder_Z;
	private BigInteger tilder;
	private BigInteger tilder_0;
	private BigInteger tildeZ;
	private BigInteger basetildeR;
	private BigInteger basetildeR_0;
	private BigInteger hatr_Z;
	private BigInteger hatr;
	private BigInteger hatr_0;
	private int bitLength;
	private QRElementPQ baseS;
	private BigInteger modN;
	private QRElementPQ baseZ;
	private BigInteger cChallenge;
	private QRElementPQ baseR;
	private QRElementPQ baseR_0;
	private final ProofStore<Object> proofStore;
	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private Map<String, BigInteger> vertexWitnessRandomNumbers;
	private Map<String, BigInteger> vertexWitnessBases;
	private Map<String, BigInteger> edgeWitnessRandomNumbers;
	private Map<String, BigInteger> edgeWitnessBases;
	private Map<URN, BigInteger> vertexResponses;
	private Map<URN, BigInteger> edgeResponses;
	private BaseCollection baseRepresentationMap;
	private Map<String, BigInteger> edgeBases;
	private ExtendedPublicKey extendedPublicKey;
	private BigInteger hatr_i;
	private BigInteger tilder_i;
	private BigInteger tilder_j;
	private BigInteger hatr_j;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private BaseCollection baseCollection;

	public GroupSetupProver(ExtendedKeyPair extendedKeyPair, ProofStore ps) {
		Assert.notNull(extendedKeyPair, "Extended key pair must not be null" );
		Assert.notNull(ps, "Proof store must not be null");
		
		this.extendedKeyPair = extendedKeyPair;
		this.extendedPublicKey = extendedKeyPair.getExtendedPublicKey();
		this.baseS = (QRElementPQ) extendedKeyPair.getPublicKey().getBaseS();
		this.modN = extendedKeyPair.getPublicKey().getModN();
		this.baseZ = (QRElementPQ) extendedKeyPair.getPublicKey().getBaseZ();
		this.baseR = (QRElementPQ) extendedKeyPair.getPublicKey().getBaseR();
		this.baseR_0 = (QRElementPQ) extendedKeyPair.getPublicKey().getBaseR_0();
		this.proofStore = ps;
		this.keyGenParameters = extendedKeyPair.getExtendedPublicKey().getKeyGenParameters();
		this.graphEncodingParameters = extendedKeyPair.getExtendedPublicKey().getGraphEncodingParameters();
		this.baseCollection = extendedKeyPair.getExtendedPublicKey().getBaseCollection();
	}

	@Override
	public void executePrecomputation() {
		// NO PRE-COMPUTATION IS NEEDED: NO-OP.
	}

	@Override
	public GroupElement executePreChallengePhase() throws ProofStoreException {
		createWitnessRandomness();
		GroupElement witness = computeWitness();
		return witness;
	}

	private void createWitnessRandomness() throws ProofStoreException {
		bitLength = computeBitlength();
		tilder_Z = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);

		tilder = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);
		tilder_0 = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);

		proofStore.store("groupsetupprover.witnesses.randomness.tilder", tilder);

		proofStore.store("groupsetupprover.witnesses.randomness.tilder_0", tilder_0);

		proofStore.store("groupsetupprover.witnesses.randomness.tilder_Z", tilder_Z);

		BigInteger vWitnessRandomness;
		BigInteger eWitnessRandomness;

		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation baseRepresentation : vertexIterator) {
			vWitnessRandomness = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);
			proofStore.store(
					"groupsetupprover.witnesses.randomness.tilder_i_" + baseRepresentation.getBaseIndex(),
					vWitnessRandomness);
		}

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation baseRepresentation : edgeIterator) {
			eWitnessRandomness = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);
			proofStore.store(
					"groupsetupprover.witnesses.randomness.tilder_j_" + baseRepresentation.getBaseIndex(),
					eWitnessRandomness);
		}
	}

	private GroupElement computeWitness() throws ProofStoreException {
		// TODO needs to work on GroupElement not raw BigInteger.
		GroupElement geTildeZ = baseS.modPow(tilder_Z);
		tildeZ = baseS.modPow(tilder_Z).getValue();
		basetildeR = baseS.modPow(tilder).getValue();
		basetildeR_0 = baseS.modPow(tilder_0).getValue();

		proofStore.store("groupsetupprover.witnesses.tildeZ", tildeZ);

		proofStore.store("groupsetupprover.witnesses.tildeR", basetildeR);

		proofStore.store("groupsetupprover.witnesses.tildeR_0", basetildeR_0);

		BigInteger vWitnessBase;
		BigInteger eWitnessBase;
		BigInteger vWitnessRandomNumber;
		BigInteger eWitnessRandomNumber;

		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation baseRepresentation : vertexIterator) {
			vWitnessRandomNumber =
					(BigInteger)
					proofStore.retrieve(
							"groupsetupprover.witnesses.randomness.tilder_i_"
									+ baseRepresentation.getBaseIndex());

			vWitnessBase = baseS.modPow(vWitnessRandomNumber).getValue();
			proofStore.store(
					"groupsetupprover.witnesses.tildeR_i_" + baseRepresentation.getBaseIndex(), vWitnessBase);
		}

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation baseRepresentation : edgeIterator) {
			eWitnessRandomNumber =
					(BigInteger)
					proofStore.retrieve(
							"groupsetupprover.witnesses.randomness.tilder_j_"
									+ baseRepresentation.getBaseIndex());
			eWitnessBase = baseS.modPow(eWitnessRandomNumber).getValue();
			proofStore.store(
					"groupsetupprover.witnesses.tildeR_j_" + baseRepresentation.getBaseIndex(), eWitnessBase);
		}
		return geTildeZ;
	}

// TODO computeChallenge should be part of an orchestrator.
	public BigInteger computeChallenge() throws NoSuchAlgorithmException {
		List<String> ctxList = populateChallengeList();
		cChallenge = CryptoUtilsFacade.computeHash(ctxList, keyGenParameters.getL_H());
		return cChallenge;
	}

	/**
	 * Post challenge phase.
	 *
	 * @throws ProofStoreException the proof store exception
	 */
	//  @Override
	public Map<URN, BigInteger> executePostChallengePhase(BigInteger cChallenge) throws ProofStoreException {

		BigInteger r_Z = extendedKeyPair.getPrivateKey().getX_rZ();
		BigInteger r = extendedKeyPair.getPrivateKey().getX_r();
		BigInteger r_0 = extendedKeyPair.getPrivateKey().getX_r0();
		BigInteger witnessRandomness;
		BigInteger vertexResponse;
		BigInteger r_i;
		BigInteger r_j;
		BigInteger edgeResponse;
		Map<URN, BigInteger> discLogs = extendedKeyPair.getExtendedPrivateKey().getDiscLogOfBases();

		vertexResponses = new HashMap<URN, BigInteger>();
		edgeResponses = new HashMap<URN, BigInteger>();
		Map<URN, BigInteger> responses = new HashMap<URN, BigInteger>();

		hatr_Z = tilder_Z.add(cChallenge.multiply(r_Z));
		hatr = tilder.add(cChallenge.multiply(r));
		hatr_0 = tilder_0.add(cChallenge.multiply(r_0));

		proofStore.store("groupsetupprover.responses.hatr_Z", hatr_Z);
		proofStore.store("groupsetupprover.responses.hatr", hatr);
		proofStore.store("groupsetupprover.responses.hatr_0", hatr_0);

		/** TODO check r_i, r_j computations */
		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation baseRepresentation : vertexIterator) {
			r_i =
					discLogs.get(
							URN.createZkpgsURN("discretelogs.vertex.R_i_" + baseRepresentation.getBaseIndex()));
			tilder_i =
					(BigInteger)
					proofStore.retrieve(
							"groupsetupprover.witnesses.randomness.tilder_i_"
									+ baseRepresentation.getBaseIndex());

			hatr_i = tilder_i.add(cChallenge.multiply(r_i));

			URN urn = URN.createZkpgsURN(
					"groupsetupprover.responses.hatr_i_" + baseRepresentation.getBaseIndex());
			vertexResponses.put(urn, hatr_i);
			responses.put(urn, hatr_i);

			proofStore.save(urn, hatr_i);
		}

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation baseRepresentation : edgeIterator) {
			r_j =
					discLogs.get(
							URN.createZkpgsURN("discretelogs.edge.R_i_j_" + baseRepresentation.getBaseIndex()));
			tilder_j =
					(BigInteger)
					proofStore.retrieve(
							"groupsetupprover.witnesses.randomness.tilder_j_"
									+ baseRepresentation.getBaseIndex());

			hatr_j = tilder_j.add(cChallenge.multiply(r_j));

			URN urn = URN.createZkpgsURN(
					"groupsetupprover.responses.hatr_i_j_" + baseRepresentation.getBaseIndex());
			edgeResponses.put(urn, hatr_j);
			responses.put(urn, hatr_j);

			proofStore.save(urn, hatr_j);
		}
		return responses;
	}

	private int computeBitlength() {
		return keyGenParameters.getL_n() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H();
	}

	private List<String> populateChallengeList() {
		GSContext gsContext =
				new GSContext(extendedPublicKey);
		List<String> ctxList = gsContext.computeChallengeContext();

		ctxList.add(String.valueOf(tildeZ));
		ctxList.add(String.valueOf(basetildeR));
		ctxList.add(String.valueOf(basetildeR_0));

		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation baseRepresentation : vertexIterator) {
			tilder_i =
					(BigInteger)
					proofStore.retrieve(
							"groupsetupprover.witnesses.tildeR_i_" + baseRepresentation.getBaseIndex());
			ctxList.add(String.valueOf(tilder_i));
		}

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation baseRepresentation : edgeIterator) {
			tilder_j =
					(BigInteger)
					proofStore.retrieve(
							"groupsetupprover.witnesses.tildeR_j_" + baseRepresentation.getBaseIndex());
			ctxList.add(String.valueOf(tilder_j));
		}

		return ctxList;
	}

	/**
	 * Output proof signature proof signature.
	 *
	 * @return the proof signature
	 */
	public ProofSignature outputProofSignature() {

		Map<URN, Object> proofSignatureElements = new HashMap<>();

		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.modN"), this.modN);
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.baseS"), this.baseS);
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.baseZ"), this.baseZ);
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.baseR"), this.baseR);
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.baseR_0"), this.baseR_0);
		BaseRepresentation baseR;

		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation baseRepresentation : vertexIterator) {
			proofSignatureElements.put(
					URN.createZkpgsURN("proofsignature.P.R_i_" + baseRepresentation.getBaseIndex()),
					baseRepresentation);
		}

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation baseRepresentation : edgeIterator) {
			proofSignatureElements.put(
					URN.createZkpgsURN("proofsignature.P.R_i_j_" + baseRepresentation.getBaseIndex()),
					baseRepresentation);
		}

		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_Z"), this.hatr_Z);
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr"), this.hatr);
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_0"), this.hatr_0);
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_i"), this.vertexResponses);
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_i_j"), this.edgeResponses);
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.c"), cChallenge);

		return new ProofSignature(proofSignatureElements);
	}

	public boolean isSetupComplete() {
		return false;
	}

	@Override
	public boolean verify() {
		return false;
	}

	public List<URN> getGovernedURNs() {
		throw new NotImplementedException("Part of the new prover interface not implemented, yet.");
	}
}
