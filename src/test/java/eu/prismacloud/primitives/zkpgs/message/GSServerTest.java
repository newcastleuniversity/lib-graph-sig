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
class GSServerTest {
  private GSServer server;
  private Logger log = GSLoggerConfiguration.getGSlog();

  @BeforeAll
  void setUp() throws IOException {
    server = new GSServer();
    server.setup();
  }

  @Test
  void testServer() throws IOException, ClassNotFoundException {
    // construct first message to client
    Map<URN, Object> msgList = new HashMap<>();
    msgList.put(URN.createZkpgsURN("test2"), BigInteger.valueOf(2342341));
    GSMessage msg = new GSMessage(msgList);

    // receive message from client
    GSMessage clientMessage = server.receive();
    assertNotNull(clientMessage);

    // send first message to client
    server.send(msg);

    Map<URN, Object> msgElements = clientMessage.getMessageElements();
    assertNotNull(msgElements);
    assertEquals(1, msgElements.size());

    for (Object value : msgElements.values()) {
      assertEquals(BigInteger.valueOf(999999), value);
      log.info("received element from client: " + value);
    }

    // construct second message to client
    msgList = new HashMap<>();
    msgList.put(URN.createZkpgsURN("test3"), BigInteger.valueOf(6666666));
    msg = new GSMessage(msgList);

    // receive second message from client
    clientMessage = server.receive();

    // send second message to client
    server.send(msg);

    msgElements = clientMessage.getMessageElements();
    assertNotNull(msgElements);
    assertEquals(1, msgElements.size());

    for (Object value : msgElements.values()) {
      assertEquals(BigInteger.valueOf(888888), value);
      log.info("received element from client: " + value);
    }

    server.close();
  }
}
