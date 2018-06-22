package eu.prismacloud.primitives.zkpgs.message;

import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.util.logging.Level;
import java.util.logging.Logger;

/** */
public class MessageGatewayImpl implements IMessageGateway {
  Logger gslog = GSLoggerConfiguration.getGSlog();

  @Override
  public void sendMessage(IMessage message) {

    gslog.log(Level.INFO, "send message: " + message);
  }
}
