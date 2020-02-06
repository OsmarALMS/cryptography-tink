package com.vodafone.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class Utils {

	public static Map<String, String> argsToMap(String[] args) throws Exception {
		final Map<String, String> params = new HashMap<String, String>();
		try {
			
			if(args.toString().contains("help")) Help.showHelp();
			for (int i = 0; i < args.length; i++) {
				final String a = args[i];

				if (a.charAt(0) == '-') {
					params.put(a.replace("-", "").toLowerCase(), args[i+1]);
				}
			}
			
			if(params.get("in") == null) Help.showHelp();
			if(params.get("genkey") == null) params.put("genkey", "true");
			if(params.get("decrypt") == null) params.put("decrypt", "false");
			if(params.get("kms") == null) params.put("dekmscrypt", "true");
			
		} catch (IndexOutOfBoundsException e) {
			System.out.println("Invalid Usage!");
			Help.showHelp();
		} catch (Exception e) {
			throw e;
		}
		return params;
	}
	
	public static Properties getExternalProperties(Map<String, String> args)  throws Exception{
		Properties properties = new Properties();
		InputStreamReader in = null;
		try {
			in = new InputStreamReader(new FileInputStream(
					args.get("p") != null ? args.get("p") : "cryptography.properties"), 
					"UTF-8");
			properties.load(in);
		}  catch (FileNotFoundException e) {
			System.out.println("File .properties not found!");
			System.exit(1);
		} catch (Exception e) {
			throw e;
		}finally {
			if (null != in) {
				try {
					in.close();
				} catch (IOException ex) {}
			}
		}
		return properties;
	}
	
}
