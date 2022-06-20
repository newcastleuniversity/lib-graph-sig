package uk.ac.ncl.cascade.integration;

import uk.ac.ncl.cascade.zkpgs.message.GSMessage;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.logging.Logger;

/**
 * Mock gateway proxy for testing orchestrators
 */

import uk.ac.ncl.cascade.zkpgs.store.URN;

/**
 * Mock gateway proxy for testing orchestrator
 */
public class MockGatewayProxy implements IMessageGateway {
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private Deque<GSMessage> messageList = new ArrayDeque<>();
	private GSMessage temp;

	public MockGatewayProxy(String type, String hostAddress, Integer portNumber) {
	}

	@Override
	public void init() throws IOException {
//		gslog.info("init");

	}

	@Override
	public void send(GSMessage message) throws IOException {
		gslog.info("send message: " + message.getMessageElements() + "\n");

		temp = new GSMessage();
		if (message.getMessageElements().get(URN.createUnsafeZkpgsURN("proof.request")) != null && !messageList.contains(temp)) {
			messageList.addFirst(message);
		}

		if (message.getMessageElements().size() >= 1) {
			messageList.addFirst(message);
		}

	}

	@Override
	public GSMessage receive() throws IOException {
		GSMessage gsMessage = new GSMessage();

		if (messageList != null && !messageList.isEmpty()) {
			gsMessage = messageList.pollLast();
		}
		gslog.info("receive message: " + gsMessage.getMessageElements() + "\n");

		return gsMessage;
	}

	@Override
	public void close() throws IOException {
//		gslog.info("close connection");
	}
}
