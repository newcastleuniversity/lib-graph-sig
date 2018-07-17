package eu.prismacloud.primitives.zkpgs.message;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
class GSClientTest {
  private GSClient client;
  private Logger log = GSLoggerConfiguration.getGSlog();

  @BeforeAll
  void setUp() throws IOException {
    client = new GSClient();
    client.setup();
  }

  @Test
  void testClient() throws IOException, ClassNotFoundException {
    /* Create The Message Object to send */
    Map<URN, Object> msgList = new HashMap<>();
    msgList.put(URN.createZkpgsURN("test1"), BigInteger.valueOf(999999));
    GSMessage msg = new GSMessage(msgList);

    client.send(msg);
    GSMessage msgFromServer = client.receive();
    Map<URN, Object> inFromServerList = msgFromServer.messageElements;
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
    inFromServerList = msgFromServer.messageElements;
    assertNotNull(inFromServerList);
    assertEquals(1, inFromServerList.size());
    for (Object value : inFromServerList.values()) {
      assertEquals(BigInteger.valueOf(6666666), value);
      log.info("received element from server: " + value);
    }

    client.close();
  }
}
