package uk.ac.ncl.cascade.zkpgs.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/** Configure utility logger class for the graph signature library. */
public class GSLoggerConfiguration {

  private static Logger gslog;

  private GSLoggerConfiguration() {}

  private static final String LOGGING_FILE = "logging.properties";

  static {
    InputStream stream =
        GSLoggerConfiguration.class.getClassLoader().getResourceAsStream(LOGGING_FILE);

    try {

      LogManager.getLogManager().readConfiguration(stream);
      gslog = Logger.getLogger(GSLoggerConfiguration.class.getName());

    } catch (IOException e) {
      System.err.println("logging.properties files cannot be opened " + e.getMessage());
    }
  }

  public static Logger getGSlog() {
    return gslog;
  }
}
