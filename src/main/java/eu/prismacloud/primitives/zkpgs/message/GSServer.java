package eu.prismacloud.primitives.zkpgs.message;

import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/** */
public class GSServer {
  private final ServerSocket welcomeSocket;
  private static final int PORT = 9999;
  private Socket clientSocket;
  private Logger log = GSLoggerConfiguration.getGSlog();
  private ObjectOutputStream outToClient;
  private ObjectInputStream inFromClient;

  public GSServer() throws IOException {
    welcomeSocket = new ServerSocket(PORT);
  }

  public void setup() throws IOException {
    // Create the Client Socket
    clientSocket = welcomeSocket.accept();
    log.info("Server Socket Established...");
    // Create input and output streams to client
    outToClient = new ObjectOutputStream(clientSocket.getOutputStream());
    inFromClient = new ObjectInputStream(clientSocket.getInputStream());

  }

  public void send(GSMessage msg) throws IOException {
    outToClient.writeObject(msg);
  }

  public GSMessage receive() throws IOException, ClassNotFoundException {
    GSMessage inMsg = (GSMessage) inFromClient.readObject();
    return inMsg;
  }

  public void close() throws IOException {
    welcomeSocket.close();
  }
}
