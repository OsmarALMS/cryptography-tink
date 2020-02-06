package pt.com.celfocus.utils;

public class Help {

	public static void showHelp(){
		System.out.println(" ==> HELP");
		System.out.println("=========================================================================== ");
		System.out.println("usage: java -jar cryptography.jar [args]");
		System.out.println("	-in 		[/input/file1.txt]			REQUIRED");
		System.out.println("	-out		[/output/file1.txt.enc]			OPTIONAL	default: [in].enc");
		System.out.println("	-meta		[/meta/file1.txt.meta]			OPTIONAL	default: [in].meta");
		System.out.println("	-genkey		[true/false]				OPTIONAL	default: [true]");
		System.out.println("	-key		[/key/file1.txt.key]			OPTIONAL	default: [in].key");
		System.out.println("	-p		[/properties/file1.properties]		OPTIONAL	cryptography.properties");
		System.out.println("	-aad		[aad]					OPTIONAL	default (.properties [aad])");
		System.out.println("	-decrypt	[true/false]				OPTIONAL	default: [false]");
		System.out.println("	-kms		[true/false]				OPTIONAL	default: [true]");
		System.out.println("=========================================================================== ");
		System.exit(1);
	}
	
}
