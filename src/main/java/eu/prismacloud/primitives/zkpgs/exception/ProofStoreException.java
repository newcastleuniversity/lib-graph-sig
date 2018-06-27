package eu.prismacloud.primitives.zkpgs.exception;


public class ProofStoreException extends Exception {

  public ProofStoreException(String message) {
    super(message);
  }

  public ProofStoreException(String message, Throwable throwable) {
    super(message, throwable);
  }
}
