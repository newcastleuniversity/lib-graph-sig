package eu.prismacloud.primitives.zkpgs.orchestrator;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.prover.SigningQCorrectnessProver;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

public class SigningQProverOrchestrator implements IProverOrchestrator {

	private Logger gslog = GSLoggerConfiguration.getGSlog();

	private final GSSignature gsSignature;
	private final BigInteger nonce;
	private final ExtendedKeyPair ekp;
	private final ExtendedPublicKey epk;
	private final KeyGenParameters keyGenParameters;
	private final ProofStore<Object> proofStore;
	private final SigningQCorrectnessProver prover;
	private List<String> contextList;

	private BigInteger cPrime;

	private List<String> challengeList;

	private GroupElement R_0;

	private GSCommitment U;

	private BigInteger hatd;

	public SigningQProverOrchestrator(GSSignature gsSignature, BigInteger nonce, ExtendedKeyPair ekp, ProofStore<Object> ps) {
		this.gsSignature = gsSignature;
		this.nonce = nonce;
		this.ekp = ekp;
		this.epk = ekp.getExtendedPublicKey();
		this.keyGenParameters = ekp.getKeyGenParameters();
		this.proofStore = ps;
		this.prover = new SigningQCorrectnessProver(gsSignature, nonce, ekp.getBaseKeyPair(), ps);
	}

	@Override
	public void init() throws IOException {

	}

	@Override
	public void executePreChallengePhase() {
		try {
			prover.executeCompoundPreChallengePhase();
		} catch (ProofStoreException e) {
			gslog.log(Level.SEVERE, "ProofStore elements not found.", e);
		}
	}

	@Override
	public void executePostChallengePhase(BigInteger cChallenge) {
		Map<URN, BigInteger> responses;
		try {
			responses = prover.executePostChallengePhase(cChallenge);
		} catch (ProofStoreException e) {
			gslog.log(Level.SEVERE, "ProofStore could not be successfully accessed.", e);
			return;
		}
		this.hatd = responses.get(URN.createZkpgsURN(URNType.buildURNComponent(URNType.HATD, SigningQCorrectnessProver.class)));
	}

	@Override
	public BigInteger computeChallenge() throws ProofStoreException {
		challengeList = populateChallengeList();
		try {
			cPrime = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
		} catch (NoSuchAlgorithmException e) {
			gslog.log(Level.SEVERE, "Could not compute the challenge.", e);
		}
		return cPrime;
	}

	@Override
	public ProofSignature createProofSignature() {
		HashMap<URN, Object> p2ProofSignatureElements = new HashMap<URN, Object>();
		p2ProofSignatureElements.put(URN.createZkpgsURN("P_2.hatd"), hatd);
		p2ProofSignatureElements.put(URN.createZkpgsURN("P_2.cPrime"), cPrime);

		ProofSignature P_2 = new ProofSignature(p2ProofSignatureElements);

		return P_2;
	}


	private List<String> populateChallengeList() {
		challengeList = new ArrayList<String>();
		GSContext gsContext =
				new GSContext(
						epk);
		contextList = gsContext.computeChallengeContext();

		challengeList.addAll(contextList);

		R_0 = ekp.getExtendedPublicKey().getPublicKey().getBaseR_0();

		/** TODO add context to list of elements in challenge */
		challengeList.add(String.valueOf(epk.getPublicKey().getModN()));
		challengeList.add(String.valueOf(epk.getPublicKey().getBaseS()));
		challengeList.add(String.valueOf(epk.getPublicKey().getBaseZ()));
		challengeList.add(String.valueOf(epk.getPublicKey().getBaseR()));
		challengeList.add(String.valueOf(R_0));

		//		    for (BaseRepresentation baseRepresentation : basesIterator) {
		//		      challengeList.add(String.valueOf(baseRepresentation.getBase().getValue()));
		//		    }

		String uCommitmentURN = "recipient.U";
		U = (GSCommitment) proofStore.retrieve(uCommitmentURN);
		GroupElement commitmentU = U.getCommitmentValue();

		challengeList.add(String.valueOf(commitmentU));
		/** TODO fix hatU computation */
		// TODO Including hat U. Actually not really proof context for this particular ZPK.
		//		    challengeList.add(String.valueOf(hatU));
		//		    challengeList.add(String.valueOf(n_1));

		return challengeList;
	}

	@Override
	public void close() throws IOException {
		// Intentional No-Operation.
	}
}
