package eu.prismacloud.primitives.zkpgs.exception;

public class VerificationException extends Exception {

  /**
	 * 
	 */
	private static final long serialVersionUID = 6773672089753735182L;

public VerificationException(String message) {
    super(message);
  }

  public VerificationException(String message, Throwable throwable) {
    super(message, throwable);
  }
}
