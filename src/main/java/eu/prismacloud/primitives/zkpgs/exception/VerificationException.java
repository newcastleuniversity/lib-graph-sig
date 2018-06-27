package eu.prismacloud.primitives.zkpgs.exception;

public class VerificationException extends Exception {

  public VerificationException(String message) {
    super(message);
  }

  public VerificationException(String message, Throwable throwable) {
    super(message, throwable);
  }
}
