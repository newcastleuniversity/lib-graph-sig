package eu.prismacloud.primitives.zkpgs.message;

import java.io.IOException;

/**
 * Interface for sending and receiving messages for Issuing, Proving and Verifying specifications
 */
public interface IMessageGateway {
  void send(GSMessage message) throws IOException;

   GSMessage receive() throws IOException;
   void close();

}
