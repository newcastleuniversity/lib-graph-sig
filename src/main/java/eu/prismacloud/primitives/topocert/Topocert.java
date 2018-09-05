package eu.prismacloud.primitives.topocert;

import java.util.Collections;
import java.util.Iterator;
import java.util.Vector;

import jargs.gnu.CmdLineParser;


public class Topocert {

	//  public abstract void graphEncodingSetup(IGraph graph, KeyGenParameters params);

	//    ArrayList<IVertex> vertices = new ArrayList<IVertex>();
	//            ArrayList<IEdge> edges = new ArrayList<IEdge>();
	//            ArrayList<ILabel> labels = new ArrayList<ILabel>();
	//    IGraph graphEnc = new GSGraph(vertices, edges, labels);
	//    IParams encParams = new EncParams(2048, 1632, 256, 256, 1, 597, 120, 2724, 80, 256, 80, 80 ,
	// 1000, 120, 50000, 256, 16);
	//            Topocert tpc = new Topocert();
	//
	//            tpc.setup(graphEnc, encParams);

	public static void main(String[] argv) {
		TopocertCmdLineParser parser = new TopocertCmdLineParser();

		try {
			parser.parse(argv);
		} catch (CmdLineParser.UnknownOptionException e) {
			System.err.println(e.getMessage());
			parser.printUsage();
			System.exit(2);
		} catch (CmdLineParser.IllegalOptionValueException e) {
			System.err.println(e.getMessage());
			parser.printUsage();
			System.exit(2);
		}

		// Boolean Options
		Boolean keygenMode = (Boolean) parser.getOptionValue(TopocertCmdLineParser.KEYGEN);
		Boolean signMode = (Boolean) parser.getOptionValue(TopocertCmdLineParser.SIGN);
		Boolean receiveMode = (Boolean) parser.getOptionValue(TopocertCmdLineParser.RECEIVE);
		Boolean proveMode = (Boolean) parser.getOptionValue(TopocertCmdLineParser.PROVE);
		Boolean verifyMode = (Boolean) parser.getOptionValue(TopocertCmdLineParser.VERIFY);
		
		Boolean offerHelp = (Boolean) parser.getOptionValue(TopocertCmdLineParser.HELP);

		// String Options
		String graphFile = (String) parser.getOptionValue(TopocertCmdLineParser.GRAPHFILENAME, TopocertDefaultOptionValues.DEF_GRAPH);
		String paramsFile = (String) parser.getOptionValue(TopocertCmdLineParser.KEYGENPARAMS, TopocertDefaultOptionValues.DEF_KEYGEN_PARAMS);
		String encodingFile = TopocertDefaultOptionValues.DEF_COUNTRY_ENCODING;
		
		String signerKeyFile = (String) parser.getOptionValue(TopocertCmdLineParser.SIGNERKP, TopocertDefaultOptionValues.DEF_SKP);
		String epkFile = (String) parser.getOptionValue(TopocertCmdLineParser.EPK, TopocertDefaultOptionValues.DEF_EPK);
		
		// Integer Options: Zero or Multiple Queries
		@SuppressWarnings("unchecked")
		Vector<Integer> queryValues = (Vector<Integer>) parser.getOptionValues(TopocertCmdLineParser.GEOSEPQUERY);

		//
		// Main Behavior Branching
		//
		if (offerHelp != null && offerHelp.booleanValue()) {
			parser.printUsage();
			System.exit(0);
		} else if (keygenMode != null && keygenMode.booleanValue()) {
			// Initialize TOPOCERT keygen
			System.out.println("Entering TOPOCERT key generation...");
			System.out.println("  Writing signer keypair to file: " + signerKeyFile);
			System.out.println("  Writing extended public key to file: " + epkFile);
			
			System.exit(0);
		} else if (signMode != null && signMode.booleanValue()) {
			// Initialize signing, with specified signer graph file.
			System.out.println("Entering TOPOCERT Sign mode...");
			System.out.println("  Using signer keypair from file: " + signerKeyFile);
			
			System.exit(0);
		} else if (receiveMode != null && receiveMode.booleanValue()) {
			// Initialize receiving of a signature.
			System.out.println("Entering TOPOCERT Receive mode...");
			System.out.println("  Using Signer's extended public key: " + epkFile);
			
			System.exit(0);
		} else if (proveMode != null && proveMode.booleanValue()) {
			// Initialize proving
			System.out.println("Entering TOPOCERT Prove mode...");
			System.out.println("  Using Signer's extended public key: " + epkFile);
			
			System.exit(0);
		} else if (verifyMode != null && verifyMode.booleanValue()) {
			// Initialize verifying, specifying queries
			if (queryValues == null || queryValues.isEmpty() || queryValues.size() < 2) {
				System.err.println("In Verify mode, please name at least two vertices with the -q/--query option.\n");
				parser.printUsage();
				System.exit(2);
			}
			System.out.println("Entering TOPOCERT Verify mode...");
			System.out.println("  Using Signer's extended public key: " + epkFile);
			System.out.print("  Queried vertices: [ ");
			for (Iterator<Integer> iterator = queryValues.iterator(); iterator.hasNext();) {
				Integer queriedVertex = (Integer) iterator.next();
				System.out.print(queriedVertex);
				if (iterator.hasNext()) System.out.print(", ");
			}
			System.out.println(" ].");
			
			System.exit(0);
		} else {
			System.err.println("Please specify a mode to operate in.\n");
			parser.printUsage();
			System.exit(2);
		}

		System.exit(0);
	}
}
