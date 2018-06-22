package eu.prismacloud.primitives.zkpgs.encoding;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPrivateKey;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JsonIsoCountries;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.Map;

/** The type Graph encoding. */
public class GraphEncoding {

  private ExtendedPublicKey ePublicKey;
  private ExtendedPrivateKey ePrivateKey;
  private static Map<URN, BaseRepresentation> bases;
  private static Map<URN, BigInteger> discLogOfVertexBases;
  private static Map<URN, BigInteger> discLogOfEdgeBases;
  private KeyGenParameters keygenParams;
  private static GraphEncodingParameters graphEncodingParameters;
  private static Map<URN, BigInteger> countryLabels;
  private static JsonIsoCountries jsonIsoCountries;

  public GraphEncoding(
      final Map<URN, BaseRepresentation> bases,
      Map<URN, BigInteger> countryLabels,
      Map<URN, BigInteger> discLogOfVertexBases,
      Map<URN, BigInteger> discLogOfEdgeBases) {

    this.bases = bases;
    this.countryLabels = countryLabels;
    this.discLogOfVertexBases = discLogOfVertexBases;
    this.discLogOfEdgeBases = discLogOfEdgeBases;
  }


  /**
   * Graph encoding setup gs graph encoding result.
   *
   * @param keyGenPair the key generation pair (public and secrete key)
   * @param graphEncodingParameters the graph encoding parameters
   * @return the gs graph encoding result
   */
  public static GraphEncoding graphEncodingSetup(
      SignerKeyPair keyGenPair, GraphEncodingParameters graphEncodingParameters) {

    BigInteger pPrime = keyGenPair.getPrivateKey().getpPrime();
    BigInteger qPrime = keyGenPair.getPrivateKey().getqPrime();
    BigInteger upperBound = pPrime.multiply(qPrime).subtract(BigInteger.ONE);
    BigInteger baseS = keyGenPair.getPublicKey().getBaseS().getValue();
    BigInteger modN = keyGenPair.getPublicKey().getModN();

    bases = GraphRepresentation.getEncodedBases();

    jsonIsoCountries = new JsonIsoCountries();

    countryLabels = jsonIsoCountries.getCountryMap();

    return new GraphEncoding(
        bases,  countryLabels, discLogOfVertexBases, discLogOfEdgeBases);
  }

}
