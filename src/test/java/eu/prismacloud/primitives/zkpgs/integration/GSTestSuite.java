package eu.prismacloud.primitives.zkpgs.integration;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

import eu.prismacloud.primitives.zkpgs.GSRecipientTest;
import eu.prismacloud.primitives.zkpgs.GSSuite;
import eu.prismacloud.primitives.zkpgs.signer.GSSignerTest;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestPlan;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;

/** */
public class GSTestSuite {
  private Logger gslog = GSLoggerConfiguration.getGSlog();

  @Test
  @DisplayName("Test the Issuing protocol using a parallel execution of Recipient and Signer")
  void testRecipientSigner() throws InterruptedException {
    Thread.sleep(1000);
    System.setProperty("GSSuite", GSSuite.RECIPIENT_SIGNER.name());
    String property = System.getProperty("GSSuite");
    gslog.info("property: " + property);

    LauncherDiscoveryRequest request =
        LauncherDiscoveryRequestBuilder.request()
            .selectors(
                selectClass(GSSignerClientTest.class), selectClass(GSRecipientServerTest.class))
            .configurationParameter("junit.jupiter.execution.parallel.enabled", "true")
            .configurationParameter("unit.jupiter.execution.parallel.config.strategy", "fixed")
            .configurationParameter("junit.extensions.autodetection.enabled", "true")
            .build();

    executeLauncherTest(request);
  }

  @Test
  @DisplayName(
      "Test the Geo-Location separation proof using a parallel execution of Prover and Verifier")
  void testProverVerifier() throws InterruptedException {
    Thread.sleep(1000);
    System.setProperty("GSSuite", GSSuite.PROVER_VERIFIER.name());
    String property = System.getProperty("GSSuite");
    gslog.info("property: " + property);

    LauncherDiscoveryRequest request =
        LauncherDiscoveryRequestBuilder.request()
            .selectors(
                selectClass(GSProverServerTest.class), selectClass(GSVerifierClientTest.class))
            .configurationParameter("junit.jupiter.execution.parallel.enabled", "true")
            .configurationParameter("unit.jupiter.execution.parallel.config.strategy", "fixed")
            .configurationParameter("junit.extensions.autodetection.enabled", "true")
            .build();
  }

  @Test
  @DisplayName("Test the socket message interactions of the low level GSClient and GSServer")
  void testClientServer() throws InterruptedException {
    Thread.sleep(1000);
    System.setProperty("GSSuite", GSSuite.GSCLIENT_GSSERVER.name());
    String property = System.getProperty("GSSuite");
    gslog.info("property: " + property);

    LauncherDiscoveryRequest request =
        LauncherDiscoveryRequestBuilder.request()
            .selectors(selectClass(GSServerTest.class), selectClass(GSClientTest.class))
            .configurationParameter("junit.jupiter.execution.parallel.enabled", "true")
            .configurationParameter("unit.jupiter.execution.parallel.config.strategy", "fixed")
            .configurationParameter("junit.extensions.autodetection.enabled", "true")
            .build();

    executeLauncherTest(request);
  }

  @Test
  @DisplayName("Test the signer socket message interactions with the recipient")
  //      @Disabled
  //  @RepeatedTest(4)
  void testSignerMessages() throws InterruptedException {
    Thread.sleep(10000); // wait for sockets to close
    System.setProperty("GSSuite", GSSuite.RECIPIENT_SIGNER.name());
    String property = System.getProperty("GSSuite");
    gslog.info("property: " + property);

    LauncherDiscoveryRequest request =
        LauncherDiscoveryRequestBuilder.request()
            .selectors(selectClass(GSRecipientTest.class), selectClass(GSSignerTest.class))
            .configurationParameter("junit.jupiter.execution.parallel.enabled", "true")
            .configurationParameter("unit.jupiter.execution.parallel.config.strategy", "fixed")
            .configurationParameter("junit.extensions.autodetection.enabled", "true")
            .build();

    executeLauncherTest(request);

    Thread.sleep(10000); // wait for sockets to close
  }

  private void executeLauncherTest(LauncherDiscoveryRequest request) {
    Launcher launcher = LauncherFactory.create();

    TestPlan testPlan = launcher.discover(request);
    TestExecutionListener listener = new SummaryGeneratingListener();
    launcher.registerTestExecutionListeners(listener);
    launcher.execute(request);
  }

  @AfterAll
  static void tearDown() {
    System.setProperty("GSSuite", "");
  }
}
