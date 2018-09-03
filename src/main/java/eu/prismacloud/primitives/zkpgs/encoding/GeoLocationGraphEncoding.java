package eu.prismacloud.primitives.zkpgs.encoding;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JsonIsoCountries;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class GeoLocationGraphEncoding implements IGraphEncoding, Serializable {

  private static final long serialVersionUID = 6958443506399975449L;

  private final SignerPublicKey signerPublicKey;
  private Map<BigInteger, GSSignature> signatureMap;
  private final Map<URN, BigInteger> vertexRepresentatives;
  private final KeyGenParameters keyGenParameters;
  private final GraphEncodingParameters graphEncodingParameters;
  private Map<URN, BigInteger> countryLabels;
  private Map<URN, Object> certifiedPrimeRepresenatives = new HashMap<URN, Object>();

  /**
   * Creates a new geolocation graph encoding with the corresponding signer's public key. The
   * geolocation graph encoding is comprised of a map of label prime representatives that represent
   * countries according to their UN country code, and a map of vertex prime representatives used to
   * encode vertices in graphs.
   *
   * @param publicKey the signer's public key
   * @param keyGenParameters the key gen parameters
   * @param graphEncodingParameters the graph encoding parameters
   */
  public GeoLocationGraphEncoding(
      final SignerPublicKey publicKey,
      final KeyGenParameters keyGenParameters,
      final GraphEncodingParameters graphEncodingParameters) {

    this.vertexRepresentatives = new LinkedHashMap<URN, BigInteger>();
    this.signerPublicKey = publicKey;
    this.keyGenParameters = keyGenParameters;
    this.graphEncodingParameters = graphEncodingParameters;
  }

  /**
   * Setups the graph encoding used to encode graphs by first generating a map fo vertex prime
   * representatives and creating a map that holds the country label prime representatives. The
   * method checks if the label representatives are in the correct range as specified in the graph
   * encoding parameters.
   */
  public void setupEncoding() throws EncodingException {

    generateVertexRepresentatives();

    JsonIsoCountries jsonIsoCountries = new JsonIsoCountries();
    countryLabels = jsonIsoCountries.getCountryMap();

    for (BigInteger label : countryLabels.values()) {
      if (!CryptoUtilsFacade.isInRange(
          label,
          graphEncodingParameters.getLeastLabelRepresentative(),
          graphEncodingParameters.getUpperBoundLabelRepresentatives())) {
        throw new EncodingException("The label representatives exceeded the designated range.");
      }
    }
  }

  /**
   * Returns a map of vertex prime representatives used to encode vertices.
   *
   * @return the vertex prime representatives
   */
  @Override
  public Map<URN, BigInteger> getVertexRepresentatives() {
    return this.vertexRepresentatives;
  }

  /**
   * Returns a map of label prime representatives used to encode countries.
   *
   * @return the label prime representatives
   */
  @Override
  public Map<URN, BigInteger> getLabelRepresentatives() {
    return this.countryLabels;
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

  /**
   * Generates the map of vertex representatives.
   *
   * <p>The vertex representatives are chosen such that they start with the smallest permissible
   * prime value for vertex 0 and enumerate the successive primes to the successive vertex
   * representatives.
   *
   * <p>The chosen vertex representatives are guaranteed not to collide with the label encoding
   * space and are guaranteed to take at most lPrime_V space.
   *
   * @complexity This method is resource-intensive as BigInteger.nextProbablePrime() will be called
   *     l_V times.
   * @throws EncodingException if the graph encoding attempted to create a prime representative
   *     outside of the range designated for vertex encoding. This will only occur if the graph
   *     encoding parameters lPrime_V and l_V are contradicting each other, e.g, if the encoding
   *     bitlength lPrime_V is too small to encode the number of vertices l_V.
   */
  public void generateVertexRepresentatives() throws EncodingException {
    BigInteger vertexPrimeRepresentative =
        this.graphEncodingParameters.getLeastVertexRepresentative();
    Assert.notNull(vertexPrimeRepresentative, "Least vertex representative was null.");
    for (int i = 0; i < this.graphEncodingParameters.getL_V(); i++) {

      if (i == 0) {
        // The first vertex representative is chosen as the smallest prime possible.
        vertexPrimeRepresentative = this.graphEncodingParameters.getLeastVertexRepresentative();
      } else {
        // The subsequent representatives are chosen as the successive next primes.
        // This yields the most space/computation efficient encoding.
        vertexPrimeRepresentative = vertexPrimeRepresentative.nextProbablePrime();
      }

      Assert.notNull(vertexPrimeRepresentative, "Designated vertex representative was null.");

      if (!CryptoUtilsFacade.isInRange(
          vertexPrimeRepresentative,
          this.graphEncodingParameters.getLeastVertexRepresentative(),
          this.graphEncodingParameters.getUpperBoundVertexRepresentatives())) {
        throw new EncodingException(
            "The graph encoding attempted to "
                + "create a vertex representative outside of the designated range.");
      }

      this.vertexRepresentatives.put(
          URN.createZkpgsURN("vertex.representative.e_i_" + i), vertexPrimeRepresentative);
    }
  }

  @Override
  public GraphEncodingParameters getGraphEncodingParameters() {
    return graphEncodingParameters;
  }
}
