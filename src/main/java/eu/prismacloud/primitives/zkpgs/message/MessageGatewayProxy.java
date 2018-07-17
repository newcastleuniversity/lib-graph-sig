package eu.prismacloud.primitives.zkpgs.message;

import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.util.logging.Level;
import java.util.logging.Logger;

/** */
public class MessageGatewayProxy  {
  private IMessageGateway messageGateway;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  public MessageGatewayProxy(String type) {

    messageGateway = new SocketMessageGatewayImpl(type);
  }

  public void send(GSMessage message) {
    gslog.log(Level.INFO, "send proxy message" + message);
    messageGateway.send(message);
  }

  public GSMessage receive() {
    GSMessage message = messageGateway.receive();
    gslog.log(Level.INFO, "receive proxy message" + message);
    return message;
  }
}
