package uk.ac.ncl.cascade.zkpgs.message;

import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import uk.ac.ncl.cascade.zkpgs.util.Assert;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

import static uk.ac.ncl.cascade.zkpgs.DefaultValues.SERVER_BACKLOG;

/**
 * Wrapper class for Http server.
 * Creates an embedded http server using the {@link com.sun.net.httpserver.HttpServer} class.
 */
public class GSHttpServer {

	private final HttpServer httpServer;

	/**
	 * Creates a new http server with the corresponding port number.
	 *
	 * @param portNumber the port number that the http server listens to requests
	 * @throws IOException when there is a failure during communication
	 */
	public GSHttpServer(int portNumber) throws IOException {
		httpServer = HttpServer.create(new InetSocketAddress(portNumber), SERVER_BACKLOG);
		httpServer.setExecutor(Executors.newCachedThreadPool());
	}

	/**
	 * Starts the http server.
	 */
	public void start() {
		httpServer.start();
	}

	/**
	 * Stops the http server without any delay.
	 */
	public void stop() {
		httpServer.stop(0);
	}

	/**
	 * Assigns a specified path in the http server to a corresponding handler.
	 *
	 * @param path    the path in the http server
	 * @param handler the handler associated with the http server path to handle requests
	 */
	public void createContextHandlers(String path, HttpHandler handler) {
		Assert.notNull(path, "context path must not be null");
		Assert.notNull(handler, "http server handler must not be null");

		HttpContext httpContext = httpServer.createContext(path, handler);
	}
}
