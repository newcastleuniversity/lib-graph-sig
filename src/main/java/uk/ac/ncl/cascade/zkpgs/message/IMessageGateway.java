package uk.ac.ncl.cascade.zkpgs.message;

import java.io.IOException;

/**
 * Interface for sending and receiving messages for Issuing, Proving and Verifying specifications
 */
public interface IMessageGateway {
	void init() throws IOException;

	void send(GSMessage message) throws IOException;

	GSMessage receive() throws IOException;
	
	void close() throws IOException;

}
