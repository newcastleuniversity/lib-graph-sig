package uk.ac.ncl.cascade.zkpgs.exception;

public class EncodingException extends Exception {

  /**
	 * 
	 */
	private static final long serialVersionUID = -7646351251608339821L;

public EncodingException(String message) {
    super(message);
  }

  public EncodingException(String message, Throwable throwable) {
    super(message, throwable);
  }
}
