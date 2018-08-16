package eu.prismacloud.primitives.zkpgs;

public class TestSuiteFailedException extends Exception {

  public TestSuiteFailedException(String message) {
    super(message);
  }

  public TestSuiteFailedException(String message, Throwable cause) {
    super(message, cause);
  }

  public TestSuiteFailedException(Throwable cause) {
    super((cause == null) ? "" : cause.toString(), cause);
  }
}
