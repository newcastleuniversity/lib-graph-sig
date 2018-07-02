package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JsonIsoCountries;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.Map;

/** The type Extended public key. */
public class ExtendedPublicKey {

  private final SignerPublicKey signerPublicKey;
  private ExtendedPublicKey ePublicKey;
  private ExtendedPrivateKey ePrivateKey;
  private Map<URN, BaseRepresentation> bases;
  private Map<URN, BigInteger> discLogOfVertexBases;
  private Map<URN, BigInteger> discLogOfEdgeBases;
  private final KeyGenParameters keygenParams;
  private final Map<URN, BigInteger> labelRepresentatives;
  private final GraphEncodingParameters graphEncodingParameters;
  private JsonIsoCountries jsonIsoCountries;
  private Map<URN, BigInteger> countryLabels;
  private BaseRepresentation base;
  private int index = 0;
  private Map<URN, BigInteger> vertexRepresentatives;
  private BigInteger vertexPrimeRepresentative;

  /**
   * Instantiates a new Extended public key.
   *
   * @param signerPublicKey the signer key pair
   * @param keygenParams the keygen params
   * @param bases the bases
   * @param vertexRepresentatives the vertex representatives
   * @param labelRepresentatives the label representatives
   * @param graphEncodingParameters the graph encoding parameters
   */
  public ExtendedPublicKey(
      final SignerPublicKey signerPublicKey,
      final KeyGenParameters keygenParams,
      final Map<URN, BaseRepresentation> bases,
      final Map<URN, BigInteger> vertexRepresentatives,
      final Map<URN, BigInteger> labelRepresentatives,
      final GraphEncodingParameters graphEncodingParameters) {

    Assert.notNull(signerPublicKey,"public key must not be null" );
    Assert.notNull(keygenParams, "keygen parameters must not be null");
    Assert.notNull(bases, "bases must not be null");
    Assert.notNull(vertexRepresentatives, "vertex representatives must not be null");
    Assert.notNull(labelRepresentatives,"label representatives must not be null");
    Assert.notNull(graphEncodingParameters, "graph encoding parameters must not be null");

    this.signerPublicKey = signerPublicKey;
    this.keygenParams = keygenParams;
    this.bases = bases;
    this.vertexRepresentatives = vertexRepresentatives;
    this.labelRepresentatives = labelRepresentatives;
    this.graphEncodingParameters = graphEncodingParameters;
  }

  /**
   * Gets public key.
   *
   * @return the public key
   */
  public SignerPublicKey getPublicKey() {
    return this.signerPublicKey;
  }

  /**
   * Gets bases.
   *
   * @return the vertex bases
   */
  public Map<URN, BaseRepresentation> getBases() {
    return this.bases;
  }

  /**
   * Gets label representatives.
   *
   * @return the country labels
   */
  public Map<URN, BigInteger> getLabelRepresentatives() {
    return this.labelRepresentatives;
  }

  /**
   * Gets vertex representatives.
   *
   * @return the vertex representatives
   */
  public Map<URN, BigInteger> getVertexRepresentatives() {
      return this.vertexRepresentatives;
    }
}
