package eu.prismacloud.primitives.grs.utils;

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
      e.printStackTrace();
    }
  }

  public static Logger getGSlog() {
    return gslog;
  }
}
