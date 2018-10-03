package eu.prismacloud.primitives.zkpgs.message;

import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Builder class for GSHttpServer class
 */
public class GSHttpServerBuilder {
	private static Map<String, HttpHandler> handlers;
	private int port;

	private GSHttpServerBuilder() {
	}

	public static GSHttpServerBuilder httpServer() {
		handlers = new HashMap<>();
		return new GSHttpServerBuilder();
	}

	public GSHttpServerBuilder addPort(int port) {
		this.port = port;
		return this;
	}

	public GSHttpServerBuilder addHandler(String path, HttpHandler httpHandler) {
		handlers.put(path, httpHandler);
		return this;
	}

	public GSHttpServer build() throws IOException {
		GSHttpServer gsHttpServer = new GSHttpServer(port);

		for (Map.Entry entry : handlers.entrySet()) {
			String path = (String) entry.getKey();
			HttpHandler httpHandler = (HttpHandler) entry.getValue();
			gsHttpServer.createContextHandlers(path, httpHandler);
		}
		return gsHttpServer;
	}

}
