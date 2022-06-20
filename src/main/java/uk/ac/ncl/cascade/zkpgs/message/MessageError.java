package uk.ac.ncl.cascade.zkpgs.message;

import java.io.Serializable;

/**
 * Represents error codes and descriptions for the communication between two parties
 * (Prover and Verifier)
 */
public enum MessageError implements Serializable {
	
	PROOF_TYPE_NOT_SUPPORTED(33, "Proof type requested is not supported"),
	PROOF_ERROR(99, "Error during proof computation");

	private final int errorCode;
	private final String description;

	private MessageError(final int code, final String description) {
		this.errorCode = code;
		this.description = description;
	}

	public String getDescription() {
		return description;
	}

	public int getErrorCode() {
		return errorCode;
	}


	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder("{\n");
		sb.append("errorCode=").append(errorCode);
		sb.append(",\ndescription='").append(description).append('\'');
		sb.append("\n}");
		return sb.toString();
	}
}
