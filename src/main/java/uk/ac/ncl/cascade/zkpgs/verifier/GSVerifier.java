package uk.ac.ncl.cascade.zkpgs.verifier;

import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.message.GSMessage;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.IMessagePartner;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.ProofSignature;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class GSVerifier implements IMessagePartner {
	private final Map<URN, BigInteger> barV = new HashMap<>();
	private final KeyGenParameters keyGenParameters;
	private final IMessageGateway messageGateway;
	private final ExtendedPublicKey extendedPublicKey;

	public GSVerifier(final ExtendedPublicKey extendedPublicKey,
					  final IMessageGateway messageGateway) {
		this.extendedPublicKey = extendedPublicKey;
		this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
		this.messageGateway = messageGateway;
	}

	public void init() throws IOException {
		this.messageGateway.init();
	}

	public Map<URN, BigInteger> getBarV() {
		return barV;
	}

	public boolean checkLengths(ProofSignature p_3) {
		int hateLength =
				keyGenParameters.getL_prime_e()
						+ keyGenParameters.getL_statzk()
						+ keyGenParameters.getL_H()
						+ 1;
		int hatvLength =
				keyGenParameters.getL_v() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;

		// TODO Implement length check

		return false;
	}

	public void sendMessage(GSMessage messageToProver) throws IOException {
		messageGateway.send(messageToProver);
	}

	public GSMessage receiveMessage() throws IOException {
		return messageGateway.receive();
	}

	public void close() throws IOException {
		messageGateway.close();
	}

	public BigInteger computeNonce() {
		return CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
	}
}
