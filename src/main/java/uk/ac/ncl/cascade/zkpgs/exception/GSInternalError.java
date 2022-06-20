package uk.ac.ncl.cascade.zkpgs.exception;

public class GSInternalError extends Error {

  /**
	 * 
	 */
	private static final long serialVersionUID = 6773672089753735182L;

public GSInternalError(String message) {
    super(message);
  }

  public GSInternalError(String message, Throwable throwable) {
    super(message, throwable);
  }
  
  public GSInternalError(Throwable throwable) {
	    super(throwable);
	  }
}
