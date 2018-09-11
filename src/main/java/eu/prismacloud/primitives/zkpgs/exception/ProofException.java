package eu.prismacloud.primitives.zkpgs.exception;

/**
 */
public class ProofException extends Error {
	public ProofException(String message) {
		super(message);
	}

	public ProofException(String message, Throwable throwable) {
		super(message, throwable);
	}

	public ProofException(Throwable throwable) {
		super(throwable);
	}
}

