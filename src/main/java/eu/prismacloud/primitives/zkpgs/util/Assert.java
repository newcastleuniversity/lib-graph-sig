package eu.prismacloud.primitives.zkpgs.util;

/** Common precondition checks for methods and constructor */
public final class Assert {

  private Assert() {}

  /**
   * Evaluates object parameter if it is null or not.
   *
   * @param object the object
   * @param errorMsg specifies the error message for the exception
   * @return the t
   * @throws NullPointerException if {@code object} is null
   */
  public static <T> T notNull(T object, Object errorMsg) {
    if (object == null) {
      throw new NullPointerException(String.valueOf(errorMsg));
    }

    return object;
  }

  public static String notEmpty(String text, String errorMsg) {
    if (text.isEmpty()) {
      throw new IllegalArgumentException(errorMsg);
    }
    return text;
  }
}
