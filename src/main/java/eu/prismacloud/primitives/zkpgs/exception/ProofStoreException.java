package eu.prismacloud.primitives.zkpgs.exception;


public class ProofStoreException extends Exception {

  /**
	 * 
	 */
	private static final long serialVersionUID = -7508531787770465554L;

public ProofStoreException(String message) {
    super(message);
  }

  public ProofStoreException(String message, Throwable throwable) {
    super(message, throwable);
  }
}
