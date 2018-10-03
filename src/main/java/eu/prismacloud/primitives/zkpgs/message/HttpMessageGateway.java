package eu.prismacloud.primitives.zkpgs.message;

import com.sun.net.httpserver.HttpServer;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;

import javax.json.JsonObject;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

import static eu.prismacloud.primitives.zkpgs.DefaultValues.*;

/**
 */
public class HttpMessageGateway implements IMessageGateway {
	private final String hostAddress;
	private final int portNumber;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private HttpServer server;
	private GSHttpClient client;
	private HttpURLConnection con;
	private GSMessageHandler gsMessageHandler;
	private ProofSignatureHandler proofSignatureHandler;
	private ProofRequestHandler proofRequestHandler;

	public HttpMessageGateway(final String hostAddress, final int portNumber) {
		this.hostAddress = hostAddress;
		this.portNumber = portNumber;
	}

	@Override
	public void init() throws IOException {

		// create handlers
		this.gsMessageHandler = new GSMessageHandler();
		this.proofSignatureHandler = new ProofSignatureHandler();
		this.proofRequestHandler = new ProofRequestHandler();

		// create an http server
		server = createHttpServer(portNumber);
	}

	private HttpServer createHttpServer(int portNumber) throws IOException {
		HttpServer httpServer = HttpServer.create(new InetSocketAddress(portNumber), 1);
		httpServer.createContext(ROOT_CONTEXT, this.gsMessageHandler);
		httpServer.createContext(PROOF_SIGNATURE_CONTEXT, this.proofSignatureHandler);
		httpServer.createContext(PROOF_REQUEST_CONTEXT, this.proofRequestHandler);
		httpServer.setExecutor(Executors.newCachedThreadPool());
		httpServer.start();
		return httpServer;
	}


	public void send(String context, JsonObject message) throws IOException {
		String url = "http://" + this.hostAddress + ":" + this.portNumber + context;
		URL obj = new URL(url);
		con = (HttpURLConnection) obj.openConnection();
		con.setRequestMethod("POST");
		con.setDoOutput(true);
		DataOutputStream wr = new DataOutputStream(con.getOutputStream());
		wr.writeBytes(message.toString());
		wr.flush();
		wr.close();
	}

	@Override
	public void send(GSMessage message) throws IOException {

	}

	@Override
	public GSMessage receive() throws IOException {

		int responseCode = con.getResponseCode();
		gslog.info("\n Send 'POST' request to URL: " + con.getURL());
		gslog.info("\n Response Code : " + responseCode);

		BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
		String inputLine;
		StringBuffer response = new StringBuffer();

		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();

		gslog.info(response.toString());


		return new GSMessage();
	}

	@Override
	public void close() throws IOException {
		server.stop(0);
	}

}
