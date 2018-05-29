package eu.prismacloud.primitives.zkpgs.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/** Configure Java logger */
public class GSLoggerConfiguration {

  private static Logger gslog = null;

  static {
    InputStream stream =
        GSLoggerConfiguration.class.getClassLoader().getResourceAsStream("logging.properties");
    try {

      LogManager.getLogManager().readConfiguration(stream);
      gslog = Logger.getLogger(GSLoggerConfiguration.class.getName());

    } catch (IOException e) {
      System.err.println("logging.properties files cannot be opened" + e.getMessage());
    }
  }

  public static Logger getGSlog() {
    return gslog;
  }
}
