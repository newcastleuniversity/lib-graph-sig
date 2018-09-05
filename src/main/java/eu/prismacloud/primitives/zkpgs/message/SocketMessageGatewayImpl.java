package eu.prismacloud.primitives.zkpgs.message;

import java.io.IOException;

/**
 * Creates either a socket-based server or client, while implementing the message gateway interface.
 * The type of the socket-based message gateway is specified during construction of the object.
 */
public class SocketMessageGatewayImpl implements IMessageGateway {

	private String type;
	private static final String CLIENT = "client";
	private static final String SERVER = "server";
	private GSClient clientGateway;
	private GSServer serverGateway;

	/**
	 * Instantiates a new socket based message gateway for either a client or a server.
	 *
	 * @param type the type
	 */
	public SocketMessageGatewayImpl(String type) {
		this.type = type;
	}



	/**
	 * Delegates the creation of either a client or a server to the appropriate class.
	 *
	 * @param type the type of gateway to create
	 * @throws IOException If an I/O error occurs, when setting up either a client or a server.
	 */
	public void init() throws IOException {
		/** TODO refactor to a factory */
		if (CLIENT.equals(type)) {
			clientGateway = new GSClient();
			clientGateway.init();
			if (clientGateway == null) {
				throw new IOException("The client gateway could not be established.");
			}

		} else if (SERVER.equals(type)) {
			serverGateway = new GSServer();
			serverGateway.init();

			if (serverGateway == null) {
				throw new IOException("The server gateway could not be established.");
			}
		}
	}

	@Override
	public void send(GSMessage msg) throws IOException {
		if ((CLIENT.equals(type) && clientGateway == null)
				|| (SERVER.equals(type) && serverGateway == null)) {
			throw new IOException("Message gateway was not established.");
		}

		if (CLIENT.equals(type)) {
			clientGateway.send(msg);

		} else if (SERVER.equals(type)) {

			serverGateway.send(msg);

		}
	}

	@Override
	public GSMessage receive() throws IOException {
		if ((CLIENT.equals(type) && clientGateway == null)
				|| (SERVER.equals(type) && serverGateway == null)) {
			throw new IOException("Message gateway was not established.");
		}

		GSMessage message = new GSMessage();
		if (CLIENT.equals(type)) {
			try {
				message = clientGateway.receive();
			} catch (ClassNotFoundException e) {
				throw new IOException("Received message could not be deserialized.", e);
			}

		} else if (SERVER.equals(type)) {
			try {
				message = serverGateway.receive();
			} catch (ClassNotFoundException e) {
				throw new IOException("Received message could not be deserialized.", e);
			}
		}

		return message;
	}

	@Override
	public void close() throws IOException {
		if (CLIENT.equals(type)) {
			clientGateway.close();
		} else if (SERVER.equals(type)) {
			serverGateway.close();

		}
	}
}
