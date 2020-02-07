package com.vodafone;

import java.io.ByteArrayOutputStream;
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
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.io.FileUtils;
import org.json.JSONObject;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.integration.gcpkms.GcpKmsClient;
import com.google.crypto.tink.streamingaead.StreamingAeadKeyTemplates;
import com.vodafone.utils.Utils;

public class Main {

	public static void main(String[] args) throws Exception {

		Map<String, String> params = Utils.argsToMap((args));
		Properties properties = Utils.getExternalProperties(params);
		ByteArrayOutputStream bosKey = new ByteArrayOutputStream();

		TinkConfig.register();

		KeysetHandle keysetHandle = getKeysetHandle(params, properties, bosKey);
		StreamingAead streamingAead = keysetHandle.getPrimitive(StreamingAead.class);

		if(params.get("decrypt").equals("false")) {
			encrypt(streamingAead, params, properties, bosKey);
		}else if(params.get("decrypt").equals("true")) {
			decrypt(streamingAead, params, properties);
		}

	}

	public static void encrypt(StreamingAead streamingAead, Map<String, String> params, Properties properties, ByteArrayOutputStream bosKey) throws Exception {

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

		//Generate Metadata
		FileWriter metaFile = new FileWriter(params.get("meta") != null ? params.get("meta") : (params.get("in")+".enc.metadata"));
		JSONObject obj = new JSONObject()
				.put("kms",properties.getProperty("kms"))
				.put("aad", Base64.getEncoder().encodeToString(
						params.get("aad") != null ? params.get("aad").getBytes() : properties.getProperty("aad").getBytes()))
				.put("keyset", new JSONObject(bosKey.toString("UTF-8")));
		metaFile.write(obj.toString(4));
		metaFile.close();
	}

	public static void decrypt(StreamingAead streamingAead, Map<String, String> params, Properties properties) throws Exception {

		@SuppressWarnings("resource")
		FileChannel ciphertextSource = new FileInputStream(params.get("in")).getChannel();

		JSONObject jsonMetadata = getMetadataJson(params);

		ReadableByteChannel decryptingChannel = streamingAead.newDecryptingChannel(
				ciphertextSource, 
				Base64.getDecoder().decode(jsonMetadata.get("aad").toString()));

		ByteBuffer buffer = ByteBuffer.allocate(8192);
		OutputStream out = new FileOutputStream(
				new File(params.get("out") != null ? params.get("out") : (params.get("in").replace(".enc", ".dec"))));

		int cnt = 1;
		do {
			if(cnt > 0) {
				buffer.clear();
				cnt = decryptingChannel.read(buffer);
				out.write(buffer.array());
			}
		} while (cnt > 0);

		out.close();
		decryptingChannel.close();
	}

	public static KeysetHandle getKeysetHandle(Map<String, String> params, Properties properties, ByteArrayOutputStream bos) throws Exception {

		KeysetHandle keysetHandle = null;

		if(params.get("decrypt").equals("false")) {

			keysetHandle = KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES256_GCM_HKDF_4KB);

			if(params.get("kms").equals("false")) {
				CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withOutputStream(bos));
			}else if(params.get("kms").equals("true")) {
				keysetHandle.write(JsonKeysetWriter.withOutputStream(bos),
						new GcpKmsClient().withDefaultCredentials().getAead(properties.getProperty("kms")));
			}

		}else if(params.get("decrypt").equals("true")) {

			JSONObject jsonMetadata = getMetadataJson(params);

			if(params.get("kms").equals("false")) {
				keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withString(jsonMetadata.get("keyset").toString()));
			}else if(params.get("kms").equals("true")) {
				keysetHandle = KeysetHandle.read(
						JsonKeysetReader.withString(jsonMetadata.get("keyset").toString()),
						new GcpKmsClient().withDefaultCredentials().getAead(jsonMetadata.get("kms").toString()));
			}
		}
		return keysetHandle;
	}

	public static JSONObject getMetadataJson(Map<String, String> params) throws Exception {
		String keysetFilename = params.get("meta") != null ? params.get("meta") : (params.get("in")+".metadata");
		String content = FileUtils.readFileToString(new File(keysetFilename), StandardCharsets.UTF_8);
		return new JSONObject(content);
	}

}
