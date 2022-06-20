package uk.ac.ncl.cascade.zkpgs.exception;

public class NotImplementedException extends RuntimeException {

	  /**
	 * 
	 */
	private static final long serialVersionUID = -2781980547771986969L;

	public NotImplementedException(String message) {
	    super(message);
	  }

	  public NotImplementedException(String message, Throwable throwable) {
	    super(message, throwable);
	  }
}
