package eu.prismacloud.primitives.zkpgs.parameters;

import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.io.InputStream;
import java.util.logging.Logger;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

/** The type Json parameters. */
public class JSONParameters {

  private static final String GS_PARAM_FILE = "zkgs_params.json";
  private InputStream paramStream;
  private static Logger gslog = GSLoggerConfiguration.getGSlog();
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private JsonReader reader;

  /** Json parameters. */
  public JSONParameters() {
    reader = parseParamFile();
    build();
  }

  /** Parse param file. */
  public JsonReader parseParamFile() {

    paramStream = JsonIsoCountries.class.getClassLoader().getResourceAsStream(GS_PARAM_FILE);

    return Json.createReader(paramStream);
  }

  public KeyGenParameters getKeyGenParameters() {
    return this.keyGenParameters;
  }

  public GraphEncodingParameters getGraphEncodingParameters() {
    return this.graphEncodingParameters;
  }

  /** Build Keygen and graph encoding parameters objects from json file. */
  public void build() {
    JsonObject jso = reader.readObject();

    JsonObject keyGenJson = jso.getJsonObject("keyGenParameters");

    int l_n = keyGenJson.getInt("l_n");
    int l_gamma = keyGenJson.getInt("l_gamma");
    int l_rho = keyGenJson.getInt("l_rho");
    int l_m = keyGenJson.getInt("l_m");
    int l_res = keyGenJson.getInt("l_res");
    int l_e = keyGenJson.getInt("l_e");
    int l_prime_e = keyGenJson.getInt("l_prime_e");
    int l_v = keyGenJson.getInt("l_v");
    int l_statzk = keyGenJson.getInt("l_statzk");
    int l_H = keyGenJson.getInt("l_H");
    int l_r = keyGenJson.getInt("l_r");
    int l_pt = keyGenJson.getInt("l_pt");

    keyGenParameters =
        KeyGenParameters.createKeyGenParameters(
            l_n, l_gamma, l_rho, l_m, l_res, l_e, l_prime_e, l_v, l_statzk, l_H, l_r, l_pt);

    
    JsonObject graphEncodingJson = jso.getJsonObject("graphEncodingParameters");
    
    int l_V = graphEncodingJson.getInt("l_V");

    int l_prime_V = graphEncodingJson.getInt("l_prime_V");
    int l_E = graphEncodingJson.getInt("l_E");
    int l_L = graphEncodingJson.getInt("l_L");
    int l_prime_L = graphEncodingJson.getInt("l_prime_L");
    graphEncodingParameters = new GraphEncodingParameters(l_V, l_prime_V, l_E, l_L, l_prime_L);
  }
}
