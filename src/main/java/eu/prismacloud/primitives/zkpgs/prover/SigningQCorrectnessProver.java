package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.context.IContext;
import eu.prismacloud.primitives.zkpgs.context.SetupGSContext;
import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPrivateKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/** 
 * Establishes the correctness of the Signer's Strong RSA signature, with Q as pre-signing value.
 */
public class SigningQCorrectnessProver implements IProver {
	
	public static final String URNID = "issuing.signer";

	private Logger gslog = GSLoggerConfiguration.getGSlog();
	
	private final ProofStore<Object> proofStore;
	private final SignerPublicKey signerPublicKey;
	private final SignerPrivateKey signerPrivateKey;
	private final KeyGenParameters keyGenParameters;
	private final GSSignature gsSignature;
	private final BigInteger n_2;
	private BigInteger tilded;
	private GroupElement tildeA;
	private List<String> challengeList;
	private BigInteger cPrime;
	private BigInteger hatd;
	private BigInteger d;
	private GroupElement Q;
	private GroupElement A;
	

	public SigningQCorrectnessProver(final GSSignature gsSignature, final BigInteger n_2, final SignerKeyPair skp, final ProofStore ps) {
		this.proofStore = ps;
		this.signerPublicKey = skp.getPublicKey();
		this.signerPrivateKey = skp.getPrivateKey();
		this.gsSignature = gsSignature;
		this.keyGenParameters = skp.getKeyGenParameters();
		this.n_2 = n_2;
	}

	@Override
	public void executePrecomputation() {
		// NO PRE-COMPUTATION IS NEEDED: NO-OP.
	}

	public GroupElement executePreChallengePhase() throws ProofStoreException {
		
		this.Q = (QRElement) proofStore.retrieve("issuing.signer.Q");
		
		BigInteger order = signerPrivateKey.getpPrime().multiply(signerPrivateKey.getqPrime());
		
		this.tilded =
				CryptoUtilsFacade.computeRandomNumber(
						NumberConstants.TWO.getValue(), order.subtract(BigInteger.ONE));

		proofStore.store(URNType.buildURNComponent(URNType.TILDED, this.getClass()), tilded);
		tildeA = Q.modPow(tilded);

		return tildeA;
	}


	public BigInteger computeChallenge() throws NoSuchAlgorithmException {
		challengeList = populateChallengeList();
		cPrime = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
		return cPrime;
	}

	private List<String> populateChallengeList() {
		this.A = (QRElement) proofStore.retrieve("issuing.signer.A");
		
		challengeList = new ArrayList<String>();
		IContext gsContext =
				new SetupGSContext(signerPublicKey);
		List<String> contextList = gsContext.computeChallengeContext();
		gslog.info("contextlist length: " + contextList.size());
		// TODO add context list
		challengeList.addAll(contextList);
		challengeList.add(String.valueOf(Q));
		challengeList.add(String.valueOf(A));
		challengeList.add(String.valueOf(tildeA));
		challengeList.add(String.valueOf(n_2));
		
		return challengeList;
	}

	
	
	public Map<URN, BigInteger> executePostChallengePhase(BigInteger cChallenge) throws ProofStoreException {
		this.d = (BigInteger) proofStore.retrieve("issuing.signer.d");
		
		BigInteger order = signerPrivateKey.getpPrime().multiply(signerPrivateKey.getqPrime());
		hatd = (tilded.subtract(cPrime.multiply(d))).mod(order);
		Map<URN, BigInteger> responses = new HashMap<URN, BigInteger>(1);
		responses.put(URN.createZkpgsURN(URNType.buildURNComponent(URNType.HATD, this.getClass())), hatd);
		return responses;
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
