package eu.prismacloud.primitives.zkpgs.encoding;

import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** */
class GraphEncodingTest {
  SignerKeyPair signerKeyPair;
  ExtendedPublicKey publicKey;
  List<BigInteger> vertexBases;
  List<BigInteger> edgeBases;
  private KeyGenParameters keygenParams;
  private String signatureKey;
  private GraphEncoding gr;

  @BeforeEach
  void setUp() {}

  @Test
  void checkLengthOfArray() {
    //    int[] prArray = gr.getPrimeNumbers();
    //    System.out.println("number of primes: " + prArray.length);

  }

  @Test
  void getEncodingSignature() {}

  @Test
  void signEncoding() {}

  @Test
  void getExtendedPrivateKey() {}

  @Test
  void setExtendedPrivateKey() {}

  @Test
  void getExtendedPublicKey() {}

  @Test
  void setExtendedPublicKey() {}

  @Test
  void encode() {}

  @Test
  void graphEncodingSetup() {}
}
