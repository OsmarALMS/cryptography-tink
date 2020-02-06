package pt.com.celfocus;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.Map;
import java.util.Properties;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.integration.gcpkms.GcpKmsClient;
import com.google.crypto.tink.streamingaead.StreamingAeadKeyTemplates;
import com.google.gson.Gson;

import pt.com.celfocus.model.Meta;
import pt.com.celfocus.utils.Utils;

public class Main {

	public static void main(String[] args) throws Exception {

		Map<String, String> params = Utils.argsToMap((args));
		Properties properties = Utils.getExternalProperties(params);

		TinkConfig.register();

		KeysetHandle keysetHandle = getKeysetHandle(params, properties);
		StreamingAead streamingAead = keysetHandle.getPrimitive(StreamingAead.class);

		if(params.get("decrypt").equals("false")) {
			encrypt(streamingAead, params, properties);
		}else if(params.get("decrypt").equals("true")) {
			decrypt(streamingAead, params, properties);
		}

	}

	public static void encrypt(StreamingAead streamingAead, Map<String, String> params, Properties properties) throws Exception {

		@SuppressWarnings("resource")
		FileChannel ciphertextDestination =
		new FileOutputStream(new File(params.get("out") != null ? params.get("out") : (params.get("in")+".enc"))).getChannel();

		WritableByteChannel encryptingChannel =
				streamingAead.newEncryptingChannel(
						ciphertextDestination, 
						params.get("aad") != null ? params.get("aad").getBytes() : properties.getProperty("aad").getBytes());

		ByteBuffer buffer = ByteBuffer.allocate(8192);
		InputStream in = new FileInputStream(new File(params.get("in")));
		while (in.available() > 0) {
			buffer.clear();
			in.read(buffer.array());
			encryptingChannel.write(buffer);
		}

		encryptingChannel.close();
		in.close();

		//Generate MetaFile
		FileWriter metaFile = new FileWriter(params.get("meta") != null ? params.get("meta") : (params.get("in")+".meta"));
		metaFile.write(new Gson().toJson(new Meta(params.get("aad") != null ? params.get("aad") : properties.getProperty("aad"))));
		metaFile.close();

	}

	public static void decrypt(StreamingAead streamingAead, Map<String, String> params, Properties properties) throws Exception {
		
		@SuppressWarnings("resource")
		FileChannel ciphertextSource = new FileInputStream(params.get("in")).getChannel();
		
		ReadableByteChannel decryptingChannel = streamingAead.newDecryptingChannel(
				ciphertextSource, 
				params.get("aad") != null ? params.get("aad").getBytes() : properties.getProperty("aad").getBytes());
		
		ByteBuffer buffer = ByteBuffer.allocate(8192);
		OutputStream out = new FileOutputStream(
				new File(params.get("out") != null ? params.get("out") : (params.get("in")+".dec")));
		
		int cnt = 1;
		do {
			buffer.clear();
			cnt = decryptingChannel.read(buffer);
			out.write(buffer.array());
		} while (cnt > 0);
		
		out.close();
		decryptingChannel.close();
	}

	public static KeysetHandle getKeysetHandle(Map<String, String> params, Properties properties) throws Exception {

		String keysetFilename = params.get("key") != null ? params.get("key") : (params.get("in")+".key");

		KeysetHandle keysetHandle = null;

		if(params.get("genkey").equals("true") && params.get("decrypt").equals("false")) {

			keysetHandle = KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES256_GCM_HKDF_4KB);

			if(params.get("kms").equals("false")) {
				CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withFile(new File(keysetFilename)));
			}else if(params.get("kms").equals("true")) {
				keysetHandle.write(JsonKeysetWriter.withFile(new File(keysetFilename)),
						new GcpKmsClient().withDefaultCredentials().getAead(properties.getProperty("gcp-kms")));
			}

		}else if(params.get("genkey").equals("false") || params.get("decrypt").equals("true")) {

			if(params.get("key") == null) {
				System.err.println("If (-genkey=false || -decrypt=true) -key param must by declared!");
				System.exit(1);
			}

			if(params.get("kms").equals("false")) {
				keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withFile(new File(keysetFilename)));
			}else if(params.get("kms").equals("true")) {
				keysetHandle = KeysetHandle.read(
						JsonKeysetReader.withFile(new File(keysetFilename)),
						new GcpKmsClient().getAead(properties.getProperty("gcp-kms")));
			}
		}
		return keysetHandle;
	}

}
