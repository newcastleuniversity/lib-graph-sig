package eu.prismacloud.primitives.zkpgs.exception;

public class EncodingException extends Exception {

  public EncodingException(String message) {
    super(message);
  }

  public EncodingException(String message, Throwable throwable) {
    super(message, throwable);
  }
}
