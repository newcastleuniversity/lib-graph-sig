package eu.prismacloud.primitives.zkpgs.message;

/** Creates a message gateway proxy for sending and receiving messages. */
public class MessageGatewayProxy {
  private IMessageGateway messageGateway;

  /**
   * Instantiates a new message gateway proxy with a specific implementation. Currently, the socket
   * interface is supported for creating a blocking socket server and a socket client.
   *
   * @param type the type of the message gateway we create
   */
  public MessageGatewayProxy(String type) {
    messageGateway = new SocketMessageGatewayImpl(type);
  }

  /**
   * Sends a message via the message gateway proxy.
   *
   * @param message the message to send using the message gateway
   */
  public void send(GSMessage message) {
    messageGateway.send(message);
  }

  /**
   * Receives a message via the message gateway proxy.
   *
   * @return the message to receive from the message gateway proxy.
   */
  public GSMessage receive() {
    GSMessage message = messageGateway.receive();
    return message;
  }

  /** Closes the message gateway proxy. */
  public void close() {
    messageGateway.close();
  }
}
