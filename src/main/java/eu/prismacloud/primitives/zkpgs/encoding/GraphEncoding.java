package eu.prismacloud.primitives.zkpgs.encoding;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPrivateKey;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JsonIsoCountries;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** The type Graph encoding. */
public class GraphEncoding {

  private static BigInteger vertexPrimeRepresentative;
  private static List<BigInteger> vertexPrimes;
  private static SignerPublicKey publicKey;
  private static Map<BigInteger, GSSignature> signatureMap;
  private ExtendedPublicKey ePublicKey;
  private ExtendedPrivateKey ePrivateKey;
  private static Map<URN, BaseRepresentation> bases;
  private final Map<URN, BigInteger> vertexPrimeRepresentatives;
  private KeyGenParameters keyGenParameters;
  private static Map<URN, BigInteger> discLogOfVertexBases;
  private static Map<URN, BigInteger> discLogOfEdgeBases;
  private KeyGenParameters keygenParams;
  private static GraphEncodingParameters graphEncodingParameters;
  private static Map<URN, BigInteger> countryLabels;
  private static JsonIsoCountries jsonIsoCountries;
  private static Map<URN, Object> certifiedPrimeRepresenatives = new HashMap<URN, Object>();

  /**
   * Instantiates a new Graph encoding.
   *
   * @param bases the bases
   * @param vertexPrimeRepresentatives the vertex prime representatives
   * @param countryLabels the country labels
   */
  public GraphEncoding(
      final Map<URN, BaseRepresentation> bases,
      final Map<URN, BigInteger> vertexPrimeRepresentatives,
      final Map<URN, BigInteger> countryLabels) {

    this.bases = bases;
    this.vertexPrimeRepresentatives = vertexPrimeRepresentatives;
    this.countryLabels = countryLabels;
  }

  /**
   * Graph encoding setup gs graph encoding result.
   *
   * @param bases the bases
   * @param vertexPrimeRepresentatives the vertex prime representatives
   * @param publicKey the public key
   * @param keyGenParameters the key gen parameters
   * @param graphEncodingParameters the graph encoding parameters
   * @return the gs graph encoding result
   */
  public static GraphEncoding graphEncodingSetup(
      final Map<URN, BaseRepresentation> bases,
      final Map<URN, BigInteger> vertexPrimeRepresentatives,
      final SignerPublicKey publicKey,
      final KeyGenParameters keyGenParameters,
      final GraphEncodingParameters graphEncodingParameters) {

    //    bases = GraphRepresentation.getEncodedBases();
    jsonIsoCountries = new JsonIsoCountries();
    countryLabels = jsonIsoCountries.getCountryMap();

    // certify(bases, vertexPrimeRepresentatives, countryLabels );

    return new GraphEncoding(bases, vertexPrimeRepresentatives, countryLabels);
  }

  /**
   * Gets bases.
   *
   * @return the bases
   */
  public static Map<URN, BaseRepresentation> getBases() {
    return GraphEncoding.bases;
  }

  /**
   * Gets vertex prime representatives.
   *
   * @return the vertex prime representatives
   */
  public Map<URN, BigInteger> getVertexPrimeRepresentatives() {
    return this.vertexPrimeRepresentatives;
  }
  /**
   * Gets signature map.
   *
   * @return the signature map
   */
  public static Map<BigInteger, GSSignature> getSignatureMap() {
    return GraphEncoding.signatureMap;
  }
  /**
   * Gets country labels.
   *
   * @return the country labels
   */
  public static Map<URN, BigInteger> getCountryLabels() {
    return GraphEncoding.countryLabels;
  }

  /**
   * Gets certified prime represenatives.
   *
   * @return the certified prime represenatives
   */
  public static Map<URN, Object> getCertifiedPrimeRepresenatives() {
    return GraphEncoding.certifiedPrimeRepresenatives;
  }

  /**
   * Certify prime representatives.
   *
   * @param vertexPrimeRepresentatives the base representation
   * @param baseV the base v
   * @param labelRepresenatives the public key
   * @param baseL the base l
   */
  public static void certify(
      Map<URN, BigInteger> vertexPrimeRepresentatives,
      BaseRepresentation baseV,
      Map<URN, BigInteger> labelRepresenatives,
      BaseRepresentation baseL) {

    signatureMap = new HashMap<BigInteger, GSSignature>();
    GSSignature gsSignature;

    for (BigInteger vertexPrime : vertexPrimeRepresentatives.values()) {
      gsSignature = CryptoUtilsFacade.generateSignature(vertexPrime, baseV, publicKey);
      signatureMap.put(vertexPrime, gsSignature);
    }

    for (BigInteger label : labelRepresenatives.values()) {
      gsSignature = CryptoUtilsFacade.generateSignature(label, baseL, publicKey);
      signatureMap.put(label, gsSignature);
    }
  }
}
