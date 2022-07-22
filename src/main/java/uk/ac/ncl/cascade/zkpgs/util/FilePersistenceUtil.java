package uk.ac.ncl.cascade.zkpgs.util;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;

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

	public Map<String, BigInteger> readFileLinesMap(String fileName) throws IOException {
		Map<String, BigInteger> linesMap = new LinkedHashMap<String, BigInteger>();
		FileInputStream inputStream = new FileInputStream(fileName);
		Scanner sc = new Scanner(inputStream, "UTF-8");
		while (sc.hasNextLine()) {
			String key = sc.nextLine();
			String valueSt = sc.nextLine();
			BigInteger value = new BigInteger(valueSt);
			linesMap.put(key,value );
		}
		return linesMap;
	}
	public void writeFileLines(String fileName, List<String> lines) throws IOException {
		OutputStream out = new BufferedOutputStream(Files.newOutputStream(Paths.get(fileName), StandardOpenOption.APPEND));
		for (String line : lines) {
			line = line.concat("\n");
			System.out.println("line " + line);
			out.write(line.getBytes());
		}
		out.close();
	}

	public void writeFileLines(String fileName, Map<String, BigInteger> lines) throws IOException {
		File f = new File(fileName);
		if (!f.exists()) {
			f.createNewFile();
		}
		OutputStream out = new BufferedOutputStream(Files.newOutputStream(Paths.get(fileName), StandardOpenOption.APPEND));
		String key;
		String value;
		for (Map.Entry<String, BigInteger> entry : lines.entrySet()) {
			key = entry.getKey().concat("\n");
			out.write(key.getBytes());
			value = entry.getValue().toString().concat("\n");
			out.write(value.getBytes());
		}

		out.close();
	}
}
