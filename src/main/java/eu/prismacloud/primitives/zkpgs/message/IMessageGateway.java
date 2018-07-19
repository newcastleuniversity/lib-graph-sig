package eu.prismacloud.primitives.zkpgs.message;

/**
 * Interface for sending and receiving messages for Issuing, Proving and Verifying specifications
 */
public interface IMessageGateway {
  void send(GSMessage message);

   GSMessage receive();
   void close();

}
