package eu.prismacloud.primitives.zkpgs.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.EnabledOnSuite;
import eu.prismacloud.primitives.zkpgs.GSSuite;
import eu.prismacloud.primitives.zkpgs.message.GSClient;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@EnabledOnSuite(name = GSSuite.GSCLIENT_GSSERVER)
@TestInstance(Lifecycle.PER_CLASS)
class GSClientTest {
  private GSClient client;
  private Logger log = GSLoggerConfiguration.getGSlog();
  private static final int PORT = 8888;

  @BeforeAll
  void setUp() throws IOException {
    client = new GSClient(PORT);
    client.init();
  }

  @EnabledOnSuite(name = GSSuite.GSCLIENT_GSSERVER)
  @Test
  void testClient() throws IOException, ClassNotFoundException {
    /* Create The Message Object to send */
    Map<URN, Object> msgList = new HashMap<>();
    msgList.put(URN.createZkpgsURN("test1"), BigInteger.valueOf(999999));
    GSMessage msg = new GSMessage(msgList);

    client.send(msg);
    GSMessage msgFromServer = client.receive();
    Map<URN, Object> inFromServerList = msgFromServer.getMessageElements();
    assertNotNull(inFromServerList);
    assertEquals(1, inFromServerList.size());

    for (Object value : inFromServerList.values()) {
      assertEquals(BigInteger.valueOf(2342341), value);
      log.info("received element from server: " + value);
    }

    msgList = new HashMap<>();
    msgList.put(URN.createZkpgsURN("test4"), BigInteger.valueOf(888888));
    msg = new GSMessage(msgList);

    client.send(msg);
    msgFromServer = client.receive();
    inFromServerList = msgFromServer.getMessageElements();
    assertNotNull(inFromServerList);
    assertEquals(1, inFromServerList.size());
    for (Object value : inFromServerList.values()) {
      assertEquals(BigInteger.valueOf(6666666), value);
      log.info("received element from server: " + value);
    }

    client.close();
  }
}
