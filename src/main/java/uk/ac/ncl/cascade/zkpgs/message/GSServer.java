package uk.ac.ncl.cascade.zkpgs.message;

import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Logger;

/**
 * Creates a blocking server socket that waits until it receives a message from a client
 */
public class GSServer implements IMessagePartner {
	private final ServerSocket serverSocket;
	private static final int PORT = 9999;
	private String hostAddress;
	private final int portNumber;
	private Socket clientSocket;
	private Logger log = GSLoggerConfiguration.getGSlog();
	private ObjectOutputStream outToClient;
	private ObjectInputStream inFromClient;

	/**
	 * Creates a new instance of the server socket with an input port number.
	 *
	 * @param port the port number to create the server socket
	 * @throws IOException When an I/O error occurs, while creating a new ServerSocket.
	 */
	public GSServer(int port) throws IOException {
		this.portNumber = port;
		serverSocket = new ServerSocket(portNumber);// , 0, InetAddress.getByName(hostAddress));
		//		serverSocket.setSoTimeout(1000);
	}

	/**
	 * Creates a new instance of the server socket with an input host address and port number.
	 *
	 * @param hostAddress the host address for the server socket
	 * @param port        the port number for the server socket
	 * @throws IOException the io exception
	 */
	public GSServer(String hostAddress, int port) throws IOException {
		this.hostAddress = hostAddress;
		this.portNumber = port;
		serverSocket = new ServerSocket(port);// , 0, InetAddress.getByName(hostAddress));
//		serverSocket.setSoTimeout(1000);
	}

	/**
	 * Blocks for a connection to be made to the server socket until a connection is made and accepts
	 * it. Creates input and output streams to the client socket.
	 *
	 * @throws IOException If an I/O error occurs, when blocking for a connection or creating the I/O
	 *                     stream for the client.
	 */
	public void init() throws IOException {
		clientSocket = serverSocket.accept();
		outToClient = new ObjectOutputStream(clientSocket.getOutputStream());
		inFromClient = new ObjectInputStream(clientSocket.getInputStream());
	}

	/**
	 * Sends a message to the client.
	 *
	 * @param msg the message send to the client
	 * @throws IOException If an I/O error occurs, when writing the message to the client output stream.
	 */
	public void send(GSMessage msg) throws IOException {
		outToClient.writeObject(msg);
	}

	/**
	 * Receives a message from the client.
	 *
	 * @return the message from the client
	 * @throws IOException            If an I/O error occurs, when reading the message from the input stream.
	 * @throws ClassNotFoundException Class of serialized GSMessage cannot be found.
	 */
	public GSMessage receive() throws IOException, ClassNotFoundException {
		GSMessage inMsg = (GSMessage) inFromClient.readObject();
		return inMsg;
	}

	/**
	 * Closes the server socket.
	 *
	 * @throws IOException If an I/O error occurs, when closing the server socket.
	 */
	public void close() throws IOException {
		if (!serverSocket.isClosed()) {
			serverSocket.close();
		}

	}
}
