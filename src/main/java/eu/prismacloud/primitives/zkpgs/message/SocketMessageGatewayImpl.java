package eu.prismacloud.primitives.zkpgs.message;

import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/** */
public class SocketMessageGatewayImpl implements IMessageGateway {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private String type;
  private GSMessage message;
  private static final String CLIENT = "client";
  private static final String SERVER = "server";
  private GSClient clientGateway;
  private GSServer serverGateway;

  public SocketMessageGatewayImpl(String type) {
    this.type = type;

    try {
      setup(type);
    } catch (IOException e) {
      log.log(Level.SEVERE, e.getMessage());
    }
  }

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
  public void send(GSMessage msg) {

    log.info("send message to " + type + ": \n" + msg);

    if (CLIENT.equals(type)) {
      try {
        clientGateway.send(msg);
      } catch (IOException e) {
        log.log(Level.SEVERE, e.getMessage());
      }

    } else if (SERVER.equals(type)) {
      try {
        serverGateway.send(msg);
      } catch (IOException e) {
        log.log(Level.SEVERE, e.getMessage());
      }
    }
  }

  @Override
  public GSMessage receive() {
    GSMessage message = new GSMessage();
    if (CLIENT.equals(type)) {
      try {
        message = clientGateway.receive();
      } catch (ClassNotFoundException e) {
        log.log(Level.SEVERE, e.getMessage());
      } catch (IOException e) {
        log.log(Level.SEVERE, e.getMessage());
      }

    } else if (SERVER.equals(type)) {
      try {
        message = serverGateway.receive();
      } catch (ClassNotFoundException e) {
        log.log(Level.SEVERE, e.getMessage());
      } catch (IOException e) {
        log.log(Level.SEVERE, e.getMessage());
      }
    }

    log.info("receive message from " + type + ": \n" + message);
    return message;
  }

  public void close() {

    if (CLIENT.equals(type)) {
      try {
        clientGateway.close();
      } catch (IOException e) {
        log.log(Level.SEVERE, e.getMessage());
      }
    } else if (SERVER.equals(type)) {
      try {
        serverGateway.close();
      } catch (IOException e) {
        log.log(Level.SEVERE, e.getMessage());
      }
    }
    log.info("closed connection for " + type);
  }
}
