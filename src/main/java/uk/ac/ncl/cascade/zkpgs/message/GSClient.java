package uk.ac.ncl.cascade.zkpgs.message;

import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.logging.Logger;

/**
 * Creates a client stream socket and connects it to the specified server host.
 */
public class GSClient implements IMessagePartner {
	private static final String DEF_HOST = "127.0.0.1";
	private static final int PORT = 9999;
	private static final int TIMEOUT = 5000;
	private final Socket clientSocket;
	private String hostAddress;
	private int portNumber;
	private Logger log = GSLoggerConfiguration.getGSlog();
	private ObjectInputStream inFromServer;
	private ObjectOutputStream outToServer;


	/**
	 * Creates a new client stream socket in the input port number and connects it to the specified
	 * port number on the server host.
	 *
	 * @param port the port number to connect
	 * @throws IOException If an I/O error occurs, when creating a new client socket.
	 */
	public GSClient(final int port) throws IOException {
		clientSocket = new Socket();
		clientSocket.connect(new InetSocketAddress(DEF_HOST, port), TIMEOUT);
	}

	/**
	 * Creates a new client stream socket in the input port number and connects it to the
	 * port number of the server specified by its host address.
	 *
	 * @param hostAddress the host address
	 * @param portNumber  the port number
	 * @throws IOException the io exception
	 */
	public GSClient(final String hostAddress, final int portNumber) throws IOException {

		this.hostAddress = hostAddress;
		this.portNumber = portNumber;
		clientSocket = new Socket();
		clientSocket.connect(new InetSocketAddress(hostAddress, portNumber), TIMEOUT);
	}

	/**
	 * Creates new input and output streams to the server.
	 *
	 * @throws IOException If an I/O error occurs, when creating the I/O stream from the server.
	 */
	public void init() throws IOException {
		outToServer = new ObjectOutputStream(clientSocket.getOutputStream());
		inFromServer = new ObjectInputStream(clientSocket.getInputStream());
	}

	/**
	 * Sends a message to the server.
	 *
	 * @param message the message send to the server
	 * @throws IOException If an I/O error happens, when writing the message to the server output
	 *                     stream.
	 */
	public void send(GSMessage message) throws IOException {
		/* Send the Message Object to the server */
		outToServer.writeObject(message);
	}

	/**
	 * Receives a message from the server.
	 *
	 * @return the message from the server
	 * @throws IOException            If an I/O error occurs, when reading the message from the server input
	 *                                stream.
	 * @throws ClassNotFoundException Class of serialized GSMessage cannot be found.
	 */
	public GSMessage receive() throws IOException, ClassNotFoundException {
		/* Retrieve the Message Object from the server */
		GSMessage msgFromServer = (GSMessage) inFromServer.readObject();
		return msgFromServer;
	}

	/**
	 * Closes the client socket.
	 *
	 * @throws IOException If an I/O error occurs, when closing the client socket.
	 */
	public void close() throws IOException {
		clientSocket.close();
	}
}
