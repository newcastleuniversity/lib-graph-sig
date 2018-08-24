package eu.prismacloud.primitives.zkpgs.encoding;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JsonIsoCountries;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/** The type Graph encoding. */
public class GraphEncoding {

  private final SignerPublicKey signerPublicKey;
  private Map<BigInteger, GSSignature> signatureMap;
  private Map<URN, BaseRepresentation> bases;
  private Map<URN, BigInteger> vertexPrimeRepresentatives = new LinkedHashMap<>();
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private Map<URN, BigInteger> countryLabels;
  private JsonIsoCountries jsonIsoCountries;
  private Map<URN, Object> certifiedPrimeRepresenatives = new HashMap<URN, Object>();

  /**
   * Instantiates a new Graph encoding.
   *
   * @param bases the bases
   * @param vertexPrimeRepresentatives the vertex prime representatives
   * @param publicKey the country labels
   * @param keyGenParameters the key gen parameters
   * @param graphEncodingParameters the graph encoding parameters
   */
  public GraphEncoding(
      final Map<URN, BaseRepresentation> bases,
      final Map<URN, BigInteger> vertexPrimeRepresentatives,
      final SignerPublicKey publicKey,
      final KeyGenParameters keyGenParameters,
      final GraphEncodingParameters graphEncodingParameters) {

    this.bases = bases;
    this.vertexPrimeRepresentatives = vertexPrimeRepresentatives;
    this.signerPublicKey = publicKey;
    this.keyGenParameters = keyGenParameters;
    this.graphEncodingParameters = graphEncodingParameters;
  }

  /** Setups the graph encoding. */
  public void setup() {

    //    bases = GraphRepresentation.getEncodedBases();
    jsonIsoCountries = new JsonIsoCountries();
    countryLabels = jsonIsoCountries.getCountryMap();

    // certify(bases, vertexPrimeRepresentatives, countryLabels );

  }

  /**
   * Gets bases.
   *
   * @return the bases
   */
  public Map<URN, BaseRepresentation> getBases() {
    return bases;
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
   * Certify prime representatives.
   *
   * @param vertexPrimeRepresentatives the base representation
   * @param baseV the base v
   * @param labelRepresenatives the public key
   * @param baseL the base l
   */
  public void certify(
      Map<URN, BigInteger> vertexPrimeRepresentatives,
      BaseRepresentation baseV,
      Map<URN, BigInteger> labelRepresenatives,
      BaseRepresentation baseL) {

    signatureMap = new HashMap<BigInteger, GSSignature>();
    GSSignature gsSignature;

    for (BigInteger vertexPrime : vertexPrimeRepresentatives.values()) {
      gsSignature = CryptoUtilsFacade.generateSignature(vertexPrime, baseV, signerPublicKey);
      signatureMap.put(vertexPrime, gsSignature);
    }

    for (BigInteger label : labelRepresenatives.values()) {
      gsSignature = CryptoUtilsFacade.generateSignature(label, baseL, signerPublicKey);
      signatureMap.put(label, gsSignature);
    }
  }
}
