import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Run {

	private static final String groupName = "I2X3";

	public static void main(String[] args) throws Exception {
		PrivateKeyRing skr = PrivateKeyRing.getInstance();

		// Genero la coppia di chiavi RSA per cifrare/decifrare
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		keyPairGen.initialize(1024);
		KeyPair RSAKeyPair = keyPairGen.genKeyPair();

		// Genero la coppia di chiavi DSA per firmare/verificare
		keyPairGen = KeyPairGenerator.getInstance("DSA");
		keyPairGen.initialize(1024);
		KeyPair DSAKeyPair = keyPairGen.genKeyPair();

		// Inserisco le coppie di chiavi generate (RSA e DSA) nel mazzo di
		// chiavi privato
		Key key = RSAKeyPair.getPublic();
		// EPK = public encryption key
		skr.setKey(groupName + "_EPK", key, key.getAlgorithm() + "/" + key.getFormat());

		key = RSAKeyPair.getPrivate();
		// ESK = private decryption key
		skr.setKey(groupName + "_ESK", key, key.getAlgorithm() + "/" + key.getFormat());

		key = DSAKeyPair.getPublic();
		// SPK = public verification key
		skr.setKey(groupName + "_SPK", key, key.getAlgorithm() + "/" + key.getFormat());

		key = DSAKeyPair.getPrivate();
		// SSK = private signing key
		skr.setKey(groupName + "_SSK", key, key.getAlgorithm() + "/" + key.getFormat());

		// Genero una chiave AES a 128 bit
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey AESKey = keyGen.generateKey();

		// Genero una chiave DESede a 168 bit
		keyGen = KeyGenerator.getInstance("DESede");
		keyGen.init(168);
		SecretKey DESedeKey = keyGen.generateKey();

		// Inserisco le chiavi AES e DESede nel mazzo di chiavi privato
		skr.setKey(groupName + "_AES", AESKey, AESKey.getAlgorithm() + "/" + AESKey.getFormat());
		skr.setKey(groupName + "_DESede", DESedeKey, DESedeKey.getAlgorithm() + "/" + DESedeKey.getFormat());

		// Ottengo le chiavi nel KeyRing privato e le stampo a video in base64
		String epkPreload = Base64.getEncoder().encodeToString(skr.getKey("I2X3_EPK").getEncoded());
		String eskPreload = Base64.getEncoder().encodeToString(skr.getKey("I2X3_ESK").getEncoded());
		String spkPreload = Base64.getEncoder().encodeToString(skr.getKey("I2X3_SPK").getEncoded());
		String sskPreload = Base64.getEncoder().encodeToString(skr.getKey("I2X3_SSK").getEncoded());

		System.out.println("/*** CHIAVI PRIMA DELLA LOAD DAL DISCO ***/");
		System.out.println(epkPreload);
		System.out.println(eskPreload);
		System.out.println(spkPreload);
		System.out.println(sskPreload);

		skr.store(new FileOutputStream(new File("privateKeyRing.bin")), "paperino".toCharArray());
		skr.load(new FileInputStream(new File("privateKeyRing.bin")), "paperino".toCharArray());

		String epkPostload = Base64.getEncoder().encodeToString(skr.getKey("I2X3_EPK").getEncoded());
		String eskPostload = Base64.getEncoder().encodeToString(skr.getKey("I2X3_ESK").getEncoded());
		String spkPostload = Base64.getEncoder().encodeToString(skr.getKey("I2X3_SPK").getEncoded());
		String sskPostload = Base64.getEncoder().encodeToString(skr.getKey("I2X3_SSK").getEncoded());

		System.out.println("\n/*** CHIAVI DOPO LA LOAD DAL DISCO ***/");
		System.out.println(epkPostload);
		System.out.println(eskPostload);
		System.out.println(spkPostload);
		System.out.println(sskPostload);
	}

}
