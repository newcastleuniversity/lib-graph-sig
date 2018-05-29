package eu.prismacloud.primitives.zkpgs.parameters;

import java.io.InputStream;
import java.util.logging.Logger;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

/** The type Json parameters. */
public class JSONParameters {

  private static final String GS_PARAM_FILE = "zkgs_params.json";
  private InputStream paramStream;
  private static Logger gslog = null;
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private JsonReader reader;

  /** Json parameters. */
  public void JSONParameters() {
    reader = parseParamFile();
    build();
  }

  /** Parse param file. */
  public JsonReader parseParamFile() {

    paramStream = JSONParameters.class.getClassLoader().getResourceAsStream(GS_PARAM_FILE);

    return  Json.createReader(paramStream);
  }

  /** Build Keygen and graph encoding parameters objects from json file. */
  public void build() {
    JsonObject jsonObject = reader.readObject();
    int l_n = jsonObject.getInt("l_n");
    int l_gamma = jsonObject.getInt("l_gamma");
    int l_rho = jsonObject.getInt("l_rho");
    int l_m = jsonObject.getInt("l_m");
    int l_res = jsonObject.getInt("l_res");
    int l_e = jsonObject.getInt("l_e");
    int l_prime_e = jsonObject.getInt("l_prime_e");
    int l_v = jsonObject.getInt("l_v");
    int l_statzk = jsonObject.getInt("l_statzk");
    int l_H = jsonObject.getInt("l_H");
    int l_r = jsonObject.getInt("l_r");
    int l_pt = jsonObject.getInt("l_pt");

    keyGenParameters =
        new KeyGenParameters(
            l_n, l_gamma, l_rho, l_m, l_res, l_e, l_prime_e, l_v, l_statzk, l_H, l_r, l_pt);

    int l_V = jsonObject.getInt("l_V");

    int l_prime_V = jsonObject.getInt("l_prime_V");
    int l_E = jsonObject.getInt("l_E");
    int l_L = jsonObject.getInt("l_L");
    int l_prime_L = jsonObject.getInt("l_prime_L");
    graphEncodingParameters = new GraphEncodingParameters(l_V,l_prime_V,l_E,l_L,l_prime_L);
  }
}
