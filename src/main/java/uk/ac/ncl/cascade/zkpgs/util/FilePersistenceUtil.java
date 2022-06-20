package uk.ac.ncl.cascade.zkpgs.util;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * File persistence utility class used for serializing objects such as the SignerKeyPair with a very
 * large bitlength.
 *
 * <p>The FilePersistenceUtil class is used for testing purposes when we want to use an object,
 * which is costly to generate randomly.
 */
public class FilePersistenceUtil {

	public FilePersistenceUtil() {
	}

	public void write(Object serialized, String fileName) throws IOException {
		FileOutputStream fileOutputStream = new FileOutputStream(fileName);
		try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream)) {
			objectOutputStream.writeObject(serialized);
			objectOutputStream.close();
		}
		fileOutputStream.close();
	}

	public Object read(String fileName) throws IOException, ClassNotFoundException {

		FileInputStream fileInputStream = new FileInputStream(fileName);
		Object object;
		try (ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream)) {
			object = objectInputStream.readObject();
			objectInputStream.close();
		}

		fileInputStream.close();
		return object;
	}

	public List<String> readFileLines(String fileName) throws FileNotFoundException {
		List<String> lines = new ArrayList<>();
		FileInputStream inputStream = new FileInputStream(fileName);
		Scanner sc = new Scanner(inputStream, "UTF-8");
		while (sc.hasNextLine()) {
			String line = sc.nextLine();
			lines.add(line);
		}
		return lines;
	}
}
