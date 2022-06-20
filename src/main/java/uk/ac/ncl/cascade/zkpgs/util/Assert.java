package uk.ac.ncl.cascade.zkpgs.util;

import java.math.BigInteger;

/** Common precondition checks for methods and constructor */
public final class Assert {

  private Assert() {}

  /**
   * Evaluates object parameter if it is null or not.
   *
   * @param <T> the type parameter
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

  /**
   * Not empty string.
   *
   * @param text the text
   * @param errorMsg the error msg
   * @return the string
   */
  public static String notEmpty(String text, String errorMsg) {
    if (text.isEmpty()) {
      throw new IllegalArgumentException(errorMsg);
    }
    return text;
  }

  /**
   * Check length of BigInteger number.
   *
   * @param number the number to check length
   * @param length the length
   * @param errorMsg the error msg
   */
  public static void checkBitLength(BigInteger number, int length, String errorMsg) {
    if (number.bitLength() != length) {
      throw new IllegalArgumentException(errorMsg);
    }
  }

  /**
   * Check size of two numbers.
   *
   * @param sizeA the size a
   * @param sizeB the size b
   * @param errorMsg the error msg
   */
  public static void checkSize(int sizeA, int sizeB, String errorMsg) {
    if (sizeA != sizeB) {
      throw new IllegalArgumentException(errorMsg);
    }
  }
}
