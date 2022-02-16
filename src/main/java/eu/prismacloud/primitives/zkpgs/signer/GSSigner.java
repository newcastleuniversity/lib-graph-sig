package eu.prismacloud.primitives.zkpgs.signer;

import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.IMessageGateway;
import eu.prismacloud.primitives.zkpgs.message.IMessagePartner;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.IURNGoverner;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import org.jgrapht.io.ImportException;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Signer
 */
public class GSSigner implements IMessagePartner, IURNGoverner {

	private final ExtendedKeyPair extendedKeyPair;
	private final KeyGenParameters keyGenParameters;
	private final IMessageGateway messageGateway;
	private GSMessage receiveMessage;

	/**
	 * Creates a new signer.
	 *
	 * @param extendedKeyPair the extended key pair
	 * @param messageGateway  the message gateway
	 */
	public GSSigner(final ExtendedKeyPair extendedKeyPair,
					final IMessageGateway messageGateway) {
		this.extendedKeyPair = extendedKeyPair;
		this.keyGenParameters = extendedKeyPair.getKeyGenParameters();
		this.messageGateway = messageGateway;
	}

	public void init() throws IOException {
		this.messageGateway.init();
	}

	/**
	 * Initialize graph with the specified graphml file name.
	 *
	 * @param filename the graphml filename
	 * @return the graph structure
	 * @throws ImportException the import exception
	 */
	public GSGraph<GSVertex, GSEdge> initGraph(String filename) throws ImportException {
		GSGraph<GSVertex, GSEdge> gsGraph = GSGraph.createGraph(filename);
		// TODO this method does not actually initialize the encoding.

		return gsGraph;
	}

	/**
	 * Sends message using message gateway.
	 *
	 * @param signerMessageToRecipient the signer message to recipient
	 * @throws IOException the I/O exception
	 */
	public void sendMessage(GSMessage signerMessageToRecipient) throws IOException {
		messageGateway.send(signerMessageToRecipient);
	}

	/**
	 * Compute a uniformly random number nonce with length l_H.
	 *
	 * @return random number
	 */
	public BigInteger computeNonce() {
		return CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
	}

	/**
	 * Receives message from message gateway.
	 *
	 * @return the received message
	 * @throws IOException the I/O exception
	 */
	public GSMessage receiveMessage() throws IOException {
		return messageGateway.receive();
	}

	/**
	 * Closes.
	 */
	public void close() throws IOException {
		messageGateway.close();
	}
}
