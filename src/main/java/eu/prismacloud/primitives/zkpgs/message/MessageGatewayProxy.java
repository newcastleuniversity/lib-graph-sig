package eu.prismacloud.primitives.zkpgs.message;

import java.io.IOException;

/** Creates a message gateway proxy for sending and receiving messages. */
public class MessageGatewayProxy implements IMessageGateway {
  private IMessageGateway messageGateway;

  /**
   * Instantiates a new message gateway proxy with a specific implementation. Currently, the socket
   * interface is supported for creating a blocking socket server and a socket client.
   * 
   * <p>the MessageGatewayProxy must still be setup with an explict call to the setup() function.
   *
   * @param type the type of the message gateway we create
   */
  public MessageGatewayProxy(String type) {
    messageGateway = new SocketMessageGatewayImpl(type);
  }
  
  /**
   * Sets up the message gateway and seeks to establish a connection with the
   * designated communication partner.
   * 
   * @throws IOException if the connection to the partner could not be established.
   */
  @Override
public void init() throws IOException {
	 messageGateway.init();
  }

  /**
   * Sends a message via the message gateway proxy.
   *
   * @param message the message to send using the message gateway
   */
  @Override
public void send(GSMessage message) throws IOException {
    messageGateway.send(message);
  }

  /**
   * Receives a message via the message gateway proxy.
   *
   * @return the message to receive from the message gateway proxy.
   */
  @Override
public GSMessage receive() throws IOException {
    GSMessage message = messageGateway.receive();
    return message;
  }

  /** Closes the message gateway proxy. */
  @Override
public void close() throws IOException {
    messageGateway.close();
  }
}
