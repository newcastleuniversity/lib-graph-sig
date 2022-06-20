package uk.ac.ncl.cascade.zkpgs.message;

import org.junit.jupiter.api.Test;
import uk.ac.ncl.cascade.zkpgs.message.MessageError;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MessageErrorTest {

	@Test
	void getDescription() {
		MessageError msgError = MessageError.PROOF_ERROR;
		assertEquals("Error during proof computation", msgError.getDescription());
	}

	@Test
	void getErrorCode() {
		MessageError msgError = MessageError.PROOF_ERROR;
		assertEquals(99, msgError.getErrorCode());
		System.out.println(msgError.toString());

	}
}