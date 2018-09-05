package eu.prismacloud.primitives.zkpgs.message;

import java.io.IOException;

public interface IMessagePartner {
	void init() throws IOException;
	void close() throws IOException;
}
