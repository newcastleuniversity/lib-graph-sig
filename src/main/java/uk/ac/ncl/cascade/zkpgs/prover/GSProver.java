package uk.ac.ncl.cascade.zkpgs.prover;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.commitment.GSCommitment;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.message.GSMessage;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.IMessagePartner;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.BaseIterator;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class GSProver implements IMessagePartner {
	public static final String URNID = "prover";

	private final GroupElement baseR;
	private final GroupElement baseS;
	private final ExtendedPublicKey extendedPublicKey;
	private final ProofStore<Object> proofStore;
	private final KeyGenParameters keyGenParameters;
	private Map<URN, GSCommitment> commitmentMap;
	private GSSignature blindedSignature;
	private BigInteger r_i;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private final IMessageGateway messageGateway;

	public GSProver(final ExtendedPublicKey extendedPublicKey,
					final ProofStore<Object> proofStore,
					final IMessageGateway messageGateway) {

		this.extendedPublicKey = extendedPublicKey;
		this.proofStore = proofStore;
		this.messageGateway = messageGateway;
		this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
		this.baseS = extendedPublicKey.getPublicKey().getBaseS();
		this.baseR = extendedPublicKey.getPublicKey().getBaseR();
	}

	public void init() throws IOException {
		this.messageGateway.init();
	}

	public Map<URN, GSCommitment> getCommitmentMap() {
		return this.commitmentMap;
	}

	public void computeCommitments(BaseIterator vertexRepresentations) throws ProofStoreException {
		GSCommitment commitment;

		this.commitmentMap = new HashMap<URN, GSCommitment>();

		for (BaseRepresentation vertexRepresentation : vertexRepresentations) {
			/** TODO check length of randomness r */
			r_i = CryptoUtilsFacade.computeRandomNumberMinusPlus(keyGenParameters.getL_n());
			BigInteger m_i = vertexRepresentation.getExponent();
			GroupElement C_i = baseR.modPow(m_i).multiply(baseS.modPow(r_i));
			commitment = GSCommitment.createCommitment(m_i, extendedPublicKey);
//      commitment.setCommitmentValue(C_i);
			String commitmentURN = "prover.commitments.C_i_" + vertexRepresentation.getBaseIndex();
			commitmentMap.put(
					URN.createURN(URN.getZkpgsNameSpaceIdentifier(), commitmentURN), commitment);
			proofStore.store(commitmentURN, commitment);
		}

		String commmitmentMapURN = "prover.commitments.C_iMap";
		proofStore.store(commmitmentMapURN, commitmentMap);
	}

	public void computeBlindedSignature(GSSignature gsSignature) {
		blindedSignature = gsSignature.blind();
		storeBlindedGS();
	}

	private void storeBlindedGS() {
		String APrimeURN = "prover.blindedgs.signature.APrime";
		String ePrimeURN = "prover.blindedgs.signature.ePrime";
		String vPrimeURN = "prover.blindedgs.signature.vPrime";

		try {
			proofStore.store(APrimeURN, blindedSignature.getA());
			proofStore.store(ePrimeURN, blindedSignature.getEPrime());
			proofStore.store(vPrimeURN, blindedSignature.getV());
		} catch (Exception e) {
			gslog.log(Level.SEVERE, e.getMessage());
		}
	}

	public void sendMessage(GSMessage messageToVerifier) throws IOException {
		messageGateway.send(messageToVerifier);
	}

	public GSMessage receiveMessage() throws IOException {
		return messageGateway.receive();
	}

	public void close() throws IOException {
		messageGateway.close();
	}
}
