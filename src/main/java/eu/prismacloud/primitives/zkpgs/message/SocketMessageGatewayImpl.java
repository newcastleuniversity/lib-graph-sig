package eu.prismacloud.primitives.zkpgs.message;

import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Creates either a socket-based server or client, while implementing the message gateway interface.
 * The type of the socket-based message gateway is specified during construction of the object.
 */
public class SocketMessageGatewayImpl implements IMessageGateway {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private String type;
  private GSMessage message;
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

    try {
      setup(type);
    } catch (IOException e) {
      log.log(Level.SEVERE, e.getMessage() + " for " + type);
    }
  }

  /**
   * Delegates the creation of either a client or a server to the appropriate class.
   *
   * @param type the type of gateway to create
   * @throws IOException If an I/O error occurs, when setting up either a client or a server.
   */
  public void setup(String type) throws IOException {
    /** TODO refactor to a factory */
    if (CLIENT.equals(type)) {
      clientGateway = new GSClient();
      clientGateway.setup();

    } else if (SERVER.equals(type)) {
      serverGateway = new GSServer();
      serverGateway.setup();
    }
  }

  @Override
  public void send(GSMessage msg) throws IOException {
    if (CLIENT.equals(type)) {
      try {
        clientGateway.send(msg);
        log.info("send message to server: ");
      } catch (IOException e) {
        log.log(Level.SEVERE, "CLIENT: " + e.getMessage());
        throw e;
      }

    } else if (SERVER.equals(type)) {
      try {
        serverGateway.send(msg);
        log.info("send message to client: ");
      } catch (IOException e) {
        log.log(Level.SEVERE, "SERVER: " + e.getMessage());
        throw e;
      }
    }
  }

  @Override
  public GSMessage receive() {
    GSMessage message = new GSMessage();
    if (CLIENT.equals(type)) {
      try {
        message = clientGateway.receive();
        log.info("receive message from server:");
      } catch (ClassNotFoundException e) {
        log.log(Level.SEVERE, "CLIENT: " + e.getMessage());
      } catch (IOException e) {
        log.log(Level.SEVERE, "CLIENT: " + e.getMessage());
      }

    } else if (SERVER.equals(type)) {
      try {
        message = serverGateway.receive();
        log.info("receive message from client:");
      } catch (ClassNotFoundException e) {
        log.log(Level.SEVERE, "SERVER: " + e.getMessage());
      } catch (IOException e) {
        log.log(Level.SEVERE, "SERVER: " + e.getMessage());
      }
    }

    return message;
  }

  @Override
  public void close() {
    if (CLIENT.equals(type)) {
      try {
        clientGateway.close();
        log.info("closed connection for client ");
      } catch (IOException e) {
        log.log(Level.SEVERE, "CLIENT: " + e.getMessage());
      }
    } else if (SERVER.equals(type)) {
      try {

        serverGateway.close();
        log.info("closed connection for server ");
      } catch (IOException e) {
        log.log(Level.SEVERE, "SERVER: " + e.getMessage());
      }
    }
  }
}
