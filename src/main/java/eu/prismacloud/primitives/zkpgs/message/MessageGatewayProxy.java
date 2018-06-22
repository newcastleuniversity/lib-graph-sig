package eu.prismacloud.primitives.zkpgs.message;

import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.util.logging.Level;
import java.util.logging.Logger;

/** */
public class MessageGatewayProxy implements IMessageGateway {
  private IMessageGateway messageGateway;
  private Logger gslog = GSLoggerConfiguration.getGSlog();

  public MessageGatewayProxy() {
    messageGateway = new MessageGatewayImpl();
  }

  @Override
  public void sendMessage(IMessage message, Object target) {
    gslog.log(Level.INFO, "send proxy message" + message);
    messageGateway.sendMessage(message, target);
  }
}
