package eu.prismacloud.primitives.zkpgs.message;

import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.logging.Logger;

/** */
public class GSClient {
  private static final String HOST = "127.0.0.1";
  private static final int PORT = 9999;
  private final Socket clientSocket;
  private Logger log = GSLoggerConfiguration.getGSlog();
  private ObjectInputStream inFromServer;
  private ObjectOutputStream outToServer;

  public GSClient() throws IOException {
    clientSocket = new Socket(HOST, PORT);
  }

  public void setup() throws IOException {
    // Create the input & output streams to the server
    outToServer = new ObjectOutputStream(clientSocket.getOutputStream());
    inFromServer = new ObjectInputStream(clientSocket.getInputStream());
  }

  public void send(GSMessage message) throws IOException {
    /* Send the Message Object to the server */
    outToServer.writeObject(message);
  }

  public GSMessage receive() throws IOException, ClassNotFoundException {
    /* Retrieve the Message Object from the server */
    GSMessage msgFromServer = (GSMessage) inFromServer.readObject();
    return msgFromServer;
  }

  public void close() throws IOException {
    clientSocket.close();
  }
}
