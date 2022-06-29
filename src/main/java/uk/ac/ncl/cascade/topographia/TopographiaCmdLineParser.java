package uk.ac.ncl.cascade.topographia;


import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import jargs.gnu.CmdLineParser;

/**
 * Offers a CmdLineParser which prepares Topographia to run in five different
 * modes (key generation, signing, receiving, proving, and verifying).
 *
 * Allows for specification of graph files, keygen and graph encoding parameter files.
 *
 */
public class TopographiaCmdLineParser extends CmdLineParser {

	public static final Option SIGN =
			new CmdLineParser.Option.BooleanOption('s', "sign");

	public static final Option SIGN_BINDINGS =
			new CmdLineParser.Option.BooleanOption("sb");
	public static final Option RECEIVE =
			new CmdLineParser.Option.BooleanOption('r', "receive");

	public static final Option RECEIVE_BINDINGS =
			new CmdLineParser.Option.BooleanOption("rb");
	public static final Option PROVE =
			new CmdLineParser.Option.BooleanOption('p', "prove");

	public static final Option PROVE_BINDINGS =
			new CmdLineParser.Option.BooleanOption("pb");
	public static final Option VERIFY =
			new CmdLineParser.Option.BooleanOption('v', "verify");

	public static final Option VERIFY_BINDINGS =
			new CmdLineParser.Option.BooleanOption("vb");
	public static final Option KEYGEN =
			new CmdLineParser.Option.BooleanOption('k', "keygen");

	public static final Option GRAPHFILENAME =
			new CmdLineParser.Option.StringOption('g', "graph");

	public static final Option GEOSEPQUERY =
			new CmdLineParser.Option.IntegerOption('q', "query");

	public static final Option KEYGENPARAMS =
			new CmdLineParser.Option.StringOption('P', "params");

	public static final Option SIGNERKP =
			new CmdLineParser.Option.StringOption('S', "signkey");

	public static final Option EPK =
			new CmdLineParser.Option.StringOption('E', "epk");

	public static final Option GSSIGNATURE =
			new CmdLineParser.Option.StringOption('G', "gs");
	public static final Option VCRED =
			new CmdLineParser.Option.StringOption('R', "vc");


	public static final Option PSEUDONYM_FILE = new CmdLineParser.Option.StringOption('U', "pseudonym");


	public static final Option NYM = new CmdLineParser.Option.StringOption('Y', "nym");

	public static final Option HOST_ADDRESS =
			new Option.StringOption('H', "host");

	public static final Option PORT_NUMBER =
			new Option.IntegerOption('T', "port");

	public static final Option VERBOSE =
			new CmdLineParser.Option.BooleanOption('V', "verbose");

	public static final Option HELP =
			new CmdLineParser.Option.BooleanOption('h', "help");

	public static final Option VERTEX_CREDENTIAL = new CmdLineParser.Option.BooleanOption('C', "vertex_credential");

	private final List<String> optionHelpList = new ArrayList<String>();

	public Option addHelp(Option option, String help) {
		optionHelpList.add(" -" + option.shortForm() + "/--"
				+ option.longForm()
				+ ": " + help);
		return option;
	}

	/**
	 * Generates a TopographiaCmdLineParser including main options and help
	 * information for them.
	 */
	public TopographiaCmdLineParser() {
		super();
		super.addOption(KEYGEN);
		super.addOption(SIGN);
		super.addOption(RECEIVE);
		super.addOption(PROVE);
		super.addOption(VERIFY);
		super.addOption(SIGN_BINDINGS);
		super.addOption(RECEIVE_BINDINGS);
		super.addOption(PROVE_BINDINGS);
		super.addOption(VERIFY_BINDINGS);
		super.addOption(GRAPHFILENAME);
		super.addOption(GEOSEPQUERY);
		super.addOption(GSSIGNATURE);
		super.addOption(KEYGENPARAMS);
		super.addOption(SIGNERKP);
		super.addOption(EPK);
		super.addOption(HOST_ADDRESS);
		super.addOption(PORT_NUMBER);
		super.addOption(VERBOSE);
		super.addOption(VERTEX_CREDENTIAL);
		super.addOption(PSEUDONYM_FILE);
		super.addOption(NYM);
		super.addOption(HELP);

		addHelp(KEYGEN, " Generates the Signer KeyPair with given keygen options.");

		addHelp(SIGN, "   Runs TOPOGRAPHIA in Signer mode, preparing to sign a graph representation "
				+ "with a "
				+ "\n               geo-location encoding as default encoding.");
		addHelp(RECEIVE, "Runs TOPOGRAPHIA in Receiver mode, initiates a joint graph signing "
				+ "protocol with a Signer.");
		addHelp(PROVE, "  Runs TOPOGRAPHIA in Prover mode, preparing to offer geo-separation proofs to"
				+ "Receiver roles.");
		addHelp(VERIFY, " Runs TOPOGRAPHIA in Verifier mode, requesting a geo-separation proof from a Prover.");

		addHelp(SIGN_BINDINGS, "   Runs TOPOGRAPHIA in binding Signer mode, preparing to sign a graph representation "
				+ "after verifying the binding and device credentials from each node in the network.  "
				+ "\n               .");
		addHelp(RECEIVE_BINDINGS, "Runs TOPOGRAPHIA in binding Receiver mode, initiates a joint graph signing "
				+ "protocol with a binding Signer.");
		addHelp(PROVE_BINDINGS, "  Runs TOPOGRAPHIA in binding Prover mode, preparing to offer an overall proof of binding for verifiers.");
		addHelp(VERIFY_BINDINGS, " Runs TOPOGRAPHIA in binding Verifier mode, requesting a proof of binding for the overall network from a binding Prover.");
		addHelp(GRAPHFILENAME, "  Specifies a GraphML file to be used as graph.");

		addHelp(GEOSEPQUERY, "  Names verifier-known (Integer) vertices which are to be "
				+ "checked in a geo-separation proof."
				+ "\n               The option should be included at least twice for two vertices to check.");

		addHelp(GSSIGNATURE, "Specifies the filename of the graph signature obtained by the Recipient.");

		addHelp(KEYGENPARAMS, " Specifies Json file for keygen and graph encoding parameters.");

		addHelp(SIGNERKP, "Specifies the filename of the Signer keypair (in Sign mode).");

		addHelp(EPK, "    Specifies the filename of the Signer's ExtendedPublicKey.");

		addHelp(HOST_ADDRESS,  "Specifies the host address ");

		addHelp(PORT_NUMBER, "Specifies the port number");

		addHelp(VERBOSE, "Switches to verbose outputs and error messages incl. stack traces.");
		addHelp(VERTEX_CREDENTIAL, "Switches to computing binding credentials.");
		addHelp(PSEUDONYM_FILE, "Specifies file storing pseudonyms for binding credentials.");
		addHelp(NYM, "Specifies the input pseudonym for the binding credential.");
		addHelp(HELP, "   Outputs this usage help.");
	}

	/**
	 * Prints an overview of the usage/help information.
	 */
	public void printUsage() {
		System.err.println("usage: topographia [mode: {{-s,--keygen} {-s,--sign} {-sb} {-r,--receive} {-rb} {-p,--prove} {-pb} {-v,--verify} {-vb}}]"
				+"\n                [{-g,--graph} filename] [{-q,--query} vertex id] [{-G,--gs} filename]"
				+"\n                [{-P,--params} filename] [{-S,--signkey} filename] [{-E,--epk} filename]"
				+"\n				[{-H,--host} address] [{-T,--port} number]"
				+"\n                [{--verbose}] [{-Y, --nym} pseudonym]"
				+"\n                [{-h,--help}]");
		System.err.println();
		for (Iterator<String> iterator = optionHelpList.iterator(); iterator.hasNext();) {
			String help = (String) iterator.next();
			System.err.println(help);
		}
	}

	public Option[] getStdOptions() {
		return new CmdLineParser.Option[] {KEYGEN, SIGN, SIGN_BINDINGS, RECEIVE, RECEIVE_BINDINGS, PROVE, PROVE_BINDINGS, VERIFY, VERIFY_BINDINGS, GRAPHFILENAME, GEOSEPQUERY, GSSIGNATURE,
				KEYGENPARAMS, SIGNERKP, EPK, HOST_ADDRESS, PORT_NUMBER, VERBOSE, VERTEX_CREDENTIAL, NYM, HELP};
	}
}