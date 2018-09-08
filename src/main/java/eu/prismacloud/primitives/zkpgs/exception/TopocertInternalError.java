package eu.prismacloud.primitives.zkpgs.exception;

public class TopocertInternalError extends Error {

  /**
	 * 
	 */
	private static final long serialVersionUID = 6773672089753735182L;

public TopocertInternalError(String message) {
    super(message);
  }

  public TopocertInternalError(String message, Throwable throwable) {
    super(message, throwable);
  }
  
  public TopocertInternalError(Throwable throwable) {
	    super(throwable);
	  }
}
