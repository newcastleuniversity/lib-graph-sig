package eu.prismacloud.primitives.topocert;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import jargs.gnu.CmdLineParser;

/**
 * Offers a CmdLineParser which prepares TOPOCERT to run in five different
 * modes (key generation, signing, receiving, proving, and verifying).
 * 
 * Allows for specification of graph files, keygen and graph encoding parameter files.
 *
 */
public class TopocertCmdLineParser extends CmdLineParser {

	public static final Option SIGN = 
			new CmdLineParser.Option.BooleanOption('s', "sign");

	public static final Option RECEIVE = 
			new CmdLineParser.Option.BooleanOption('r', "receive");

	public static final Option PROVE = 
			new CmdLineParser.Option.BooleanOption('p', "prove");

	public static final Option VERIFY = 
			new CmdLineParser.Option.BooleanOption('v', "verify");

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
			new CmdLineParser.Option.StringOption('P', "epk");

	public static final Option HELP = 
			new CmdLineParser.Option.BooleanOption('h', "help");

	private final List<String> optionHelpList = new ArrayList<String>(); 

	public Option addHelp(Option option, String help) {
		optionHelpList.add(" -" + option.shortForm() + "/--" 
				+ option.longForm()
				+ ": " + help);
		return option;
	}

	/**
	 * Generates a TopocertCmdLineParser including main options and help 
	 * information for them.
	 */
	public TopocertCmdLineParser() {
		super();

		super.addOption(KEYGEN);
		super.addOption(SIGN);
		super.addOption(RECEIVE);
		super.addOption(PROVE);
		super.addOption(VERIFY);
		super.addOption(GRAPHFILENAME);
		super.addOption(GEOSEPQUERY);
		super.addOption(KEYGENPARAMS);
		super.addOption(SIGNERKP);
		super.addOption(EPK);
		super.addOption(HELP);

		addHelp(KEYGEN, " Generates the Signer KeyPair with given keygen options.");

		addHelp(SIGN, "   Runs TOPOCERT in Signer mode, preparing to sign a graph representation "
				+ "with a "
				+ "\n               geo-location encoding as default encoding.");
		addHelp(RECEIVE, "Runs TOPOCERT in Receiver mode, initiates a joint graph signing "
				+ "protocol with a Signer.");
		addHelp(PROVE, "  Runs TOPOCERT in Prover mode, preparing to offer geo-separation proofs to"
				+ "Receiver roles.");
		addHelp(VERIFY, " Runs TOPOCERT in Verifier mode, requesting a geo-separation proof from a Prover.");

		addHelp(GRAPHFILENAME, "  Specifies a GraphML file to be used as graph.");

		addHelp(GEOSEPQUERY, "  Names verifier-known (Integer) vertices which are to be "
				+ "checked in a geo-separation proof."
				+ "\n               The option should be included at least twice for two vertices to check.");

		addHelp(KEYGENPARAMS, " Specifies Json file for keygen and graph encoding parameters.");
		
		addHelp(SIGNERKP, "Specifies the filename of the Signer keypair (in Sign mode).");
		
		addHelp(EPK, "    Specifies the filename of the Signer's ExtendedPublicKey.");
		
		addHelp(HELP, "   Outputs this usage help.");
	}

	/**
	 * Prints an overview of the usage/help information.
	 */
	public void printUsage() {
		System.err.println("usage: topocert [mode: {{-s,--keygen} {-s,--sign} {-r,--receive} {-p,--prove} {-v,--verify}}]"
				+"\n                [{-g,--graph} filename] [{-q,--query} vertex id]"
				+"\n                [{-P,--params} filename] [{-S,--signkey} filename] [{-P,--epk} filename]"
				+"\n                [{-h,--help}]");
		System.err.println();
		for (Iterator<String> iterator = optionHelpList.iterator(); iterator.hasNext();) {
			String help = (String) iterator.next();
			System.err.println(help);
		}
	}

	public Option[] getStdOptions() {
		return new CmdLineParser.Option[] {KEYGEN, SIGN, RECEIVE, PROVE, VERIFY, GRAPHFILENAME, GEOSEPQUERY, HELP};
	}
}
