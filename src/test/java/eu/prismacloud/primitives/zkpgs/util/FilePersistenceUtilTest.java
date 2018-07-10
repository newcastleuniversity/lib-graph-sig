package eu.prismacloud.primitives.zkpgs.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroup;
import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class FilePersistenceUtilTest {
  private static final String SIGNER_KEYPAIR_FILE = "SingerKeyPair.ser";
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private FilePersistenceUtil persistenceUtil;
  private KeyGenParameters keyGenParameters;

  @BeforeEach
  void setUp() {

    JSONParameters parameters = new JSONParameters();
    keyGenParameters = parameters.getKeyGenParameters();
    GraphEncodingParameters graphEncodingParameters = parameters.getGraphEncodingParameters();
    persistenceUtil = new FilePersistenceUtil();
  }

  @Test
  void writeSignerKeyPair() throws IOException {

    gslog.info("@Test: key generation");
    SignerKeyPair gsk = new SignerKeyPair();
    gsk.keyGen(keyGenParameters);

    persistenceUtil.write(gsk, "SignerKeyPair-" + keyGenParameters.getL_n() + ".ser");
  }

  @Test
  void readSignerKeyPair() throws IOException, ClassNotFoundException {

    SignerKeyPair signerKeyPair =
        (SignerKeyPair) persistenceUtil.read("SignerKeyPair-" + keyGenParameters.getL_n() + ".ser");

    assertNotNull(signerKeyPair);
    assertNotNull(signerKeyPair.getPrivateKey());
    assertNotNull(signerKeyPair.getPublicKey());
    assertNotNull(signerKeyPair.getQRGroup());
    SignerPublicKey signerPublicKey = signerKeyPair.getPublicKey();

    Group qrGroup = signerKeyPair.getQRGroup();

    String baseRValue = "7953896389436138876961742280716204145930507979263230515233273781886841616569858708233972007838237935789101115481992283727063188869211602358338007908072351973026205107324243271454329187833323095855433721235745795531649836711823225317426103665306931916090331483765559577959230033177220495576678697539969996400861557111135366048715754410071664832633176828064862450072427006275673189590707456734677599404073977179228029374610649991505169324670428319941358615476731575902612432532933607284532765986544951257557743611258236014116400710576685550052725788472672151603910629697336899411677361947233947035266886433813800920535";

    GroupElement baseRGL = new QRElement(qrGroup, new BigInteger(baseRValue));

    assertEquals(baseRGL, signerPublicKey.getBaseR());
    gslog.info("baseR: " + signerPublicKey.getBaseR().getValue().toString());

    String baseSValue = "7098750245193150909811723801739514593351697001780869494165095484743895685337962218844373755556277245873174156476386969665338416570851360562249840809216225269928551475227252427299875688065342298745153904766197937956397352770390508163631093075028364899691444397668907550945315169568198001376066815783847417042352899442029308092411495025953217650368273920406773407716531304053589882833796524654455487725013850680682113549298748127977856493810792064716911019439526564774158380280541137640619004676671958891379079879943506390972869174563442377074385863989746127600517141173817842979520147595369694125036602574908640838973";

    GroupElement baseSGL = new QRElement(qrGroup, new BigInteger(baseSValue));
    
    assertEquals(baseSGL, signerPublicKey.getBaseS());
    gslog.info("baseS: " + signerPublicKey.getBaseS().getValue().toString());

    String modNValue = "17956334954234218366968184292387484862806907967860290874891263102842917324429624148681931013876417407954966926050430835408627033809940604948102475209798923793455632978991161921991708386467422949551938073672854235703950473539091645385958901264564368201987412253893666327442799644856882727231711872017273654486266389599390297327187203968378784373643882749241236777762122881235681321654619504332860881472678053018625432549949060909505014780116764044134873543027910905328083697193682876982832999540605202434526987893651364316352148262007596401637128963119541227787272915615538433191909613312785047537321676142376282514273";
   
    assertEquals(new BigInteger(modNValue), signerPublicKey.getModN() );
    gslog.info("modN: " + signerKeyPair.getPublicKey().getModN().toString());

    
  }
}
