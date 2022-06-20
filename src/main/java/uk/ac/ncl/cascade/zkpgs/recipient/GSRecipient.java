package uk.ac.ncl.cascade.zkpgs.recipient;

import uk.ac.ncl.cascade.zkpgs.commitment.GSCommitment;
import uk.ac.ncl.cascade.zkpgs.graph.GSEdge;
import uk.ac.ncl.cascade.zkpgs.graph.GSGraph;
import uk.ac.ncl.cascade.zkpgs.graph.GSVertex;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.message.GSMessage;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.IMessagePartner;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.store.IURNGoverner;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.util.BaseCollection;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;

import java.io.IOException;
import java.math.BigInteger;

public class GSRecipient implements IMessagePartner, IURNGoverner {

	private final ExtendedPublicKey extendedPublicKey;
	private final KeyGenParameters keyGenParameters;
	private final ProofStore<Object> recipientStore;
	private final IMessageGateway messageGateway;
	private GSGraph<GSVertex, GSEdge> recipientGraph;

	public GSRecipient(final ExtendedPublicKey extendedPublicKey,
					   final IMessageGateway messageGateway) {
		this.extendedPublicKey = extendedPublicKey;
		this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
		this.recipientStore = new ProofStore<Object>();
		this.messageGateway = messageGateway;
	}

	public void init() throws IOException {
		this.messageGateway.init();
	}

	public BigInteger generatevPrime() {
		return CryptoUtilsFacade.computeRandomNumberMinusPlus(
				this.keyGenParameters.getL_n() + this.keyGenParameters.getL_statzk());
	}

	public GSCommitment commit(BaseCollection encodedBases, BigInteger rnd) {
		GSCommitment gsCommitment = GSCommitment.createCommitment(encodedBases, rnd, extendedPublicKey);

		return gsCommitment;
	}

	public GSGraph<GSVertex, GSEdge> getRecipientGraph() {
		return this.recipientGraph;
	}

	public void sendMessage(GSMessage recMessageToSigner) throws IOException {
		messageGateway.send(recMessageToSigner);
	}

	public GSMessage receiveMessage() throws IOException {
		return messageGateway.receive();
	}

	public void setGraph(GSGraph<GSVertex, GSEdge> recipientGraph) {
		this.recipientGraph = recipientGraph;
	}

	public BigInteger generateN_2() {
		return CryptoUtilsFacade.computeRandomNumber(this.keyGenParameters.getL_H());
	}

	public void close() throws IOException {
		messageGateway.close();
	}
}
