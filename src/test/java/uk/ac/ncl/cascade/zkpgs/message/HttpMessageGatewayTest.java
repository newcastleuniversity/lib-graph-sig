package uk.ac.ncl.cascade.zkpgs.message;

import uk.ac.ncl.cascade.zkpgs.message.GSMessage;
import uk.ac.ncl.cascade.zkpgs.message.HttpMessageGateway;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import javax.json.Json;
import javax.json.JsonObject;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Logger;

import static uk.ac.ncl.cascade.zkpgs.DefaultValues.PORT;
import static uk.ac.ncl.cascade.zkpgs.DefaultValues.SERVER_ADDR;
import static org.junit.jupiter.api.Assertions.*;

/**
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class HttpMessageGatewayTest {
	private HttpMessageGateway messageGateway;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private HttpMessageGateway server;
	private HttpMessageGateway client;

	@BeforeAll
	void setupKey() throws IOException {
		server = new HttpMessageGateway(SERVER_ADDR, PORT);
		server.init();

		client = new HttpMessageGateway(SERVER_ADDR, PORT - 4);
		client.init();
	}

	@Test
	@DisplayName("Send json message to correct context for the http server")
	void testPostGSMessageHandler() throws IOException {
		String url = "http://localhost:" + PORT + "/";
		URL obj = new URL(url);
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();
		JsonObject jsonMsg = Json.createObjectBuilder().add("data", "hello").build();
		con.setRequestMethod("POST");
		con.setDoOutput(true);
		DataOutputStream wr = new DataOutputStream(con.getOutputStream());
		wr.writeBytes(jsonMsg.toString());
		wr.flush();
		wr.close();


		int responseCode = con.getResponseCode();
		gslog.info("\n Send 'POST' request to URL: " + url);
		gslog.info("\n Response Code : " + responseCode);

		BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
		String inputLine;
		StringBuffer response = new StringBuffer();

		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();

		gslog.info(response.toString());
		assertEquals(200, responseCode);
	}


	@Test
	@DisplayName("Send json message to illegal context for the http server")
	void testIllegalContextPostGSMessageHandler() throws IOException {
		String url = "http://localhost:" + PORT + "/wrong";
		URL obj = new URL(url);
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();
		JsonObject jsonMsg = Json.createObjectBuilder().add("data", "hello").build();
		con.setRequestMethod("POST");
		con.setDoOutput(true);
		DataOutputStream wr = new DataOutputStream(con.getOutputStream());
		wr.writeBytes(jsonMsg.toString());
		wr.flush();
		wr.close();

		Throwable exception = assertThrows(IOException.class, () -> {
			int responseCode = con.getResponseCode();
			gslog.info("\n Send 'POST' request to URL: " + url);
			gslog.info("\n Response Code : " + responseCode);

			BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
			String inputLine;
			StringBuffer response = new StringBuffer();

			while ((inputLine = in.readLine()) != null) {
				response.append(inputLine);
			}
			in.close();
		});
		assertEquals("Server returned HTTP response code: 400 for URL: http://localhost:9999/wrong", exception.getMessage());

	}

	@Test
	void send() throws IOException {
		JsonObject jsonMsg = Json.createObjectBuilder().add("data", "hello").build();
		GSMessage msg = new GSMessage();
		msg.messageElements.put(URN.createUnsafeZkpgsURN("test"), BigInteger.valueOf(23423423));
		client.send("/", msg.getJsonMessage());
		GSMessage message = client.receive();
		assertNotNull(message);
	}


}