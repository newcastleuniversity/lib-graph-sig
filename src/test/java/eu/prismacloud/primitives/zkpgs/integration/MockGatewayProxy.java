package eu.prismacloud.primitives.zkpgs.integration;

import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.IMessageGateway;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.logging.Logger;

/**
 * Mock gateway proxy for testing orchestrators
 */
public class MockGatewayProxy implements IMessageGateway {
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private GSMessage message;
	private static int i;
	private Deque<GSMessage> messageList = new ArrayDeque<>();

	public MockGatewayProxy(String type, String hostAddress, Integer portNumber) {
	}

	@Override
	public void init() throws IOException {
		gslog.info("init");
	}

	@Override
	public void send(GSMessage message) throws IOException {
		gslog.info("send message: " + message);
		messageList.addFirst(message);
	}

	@Override
	public GSMessage receive() throws IOException {
		GSMessage gsMessage = new GSMessage();
		if (messageList != null && !messageList.isEmpty()) {
			gsMessage = messageList.pollLast();
			gslog.info("receive message: " + gsMessage);
		}
		return gsMessage;
	}

	@Override
	public void close() throws IOException {
		gslog.info("close connection");
	}
}