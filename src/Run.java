import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Run {

	private final static String groupName = "I2X3";

	public static void main(String[] args) throws Exception {
		/*************************************************************************************************
		 ******************************* GESTIONE DEL KEYRING PRIVATO ************************************
		 ************************************************************************************************/
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

		// Ottengo le chiavi del KeyRing privato e le stampo a video in base64
		String epkPreload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_EPK").getEncoded());
		String eskPreload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_ESK").getEncoded());
		String spkPreload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_SPK").getEncoded());
		String sskPreload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_SSK").getEncoded());
		String aesPreload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_AES").getEncoded());
		String desedePreload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_DESede").getEncoded());

		System.out.println("/*** CHIAVI PRIMA DELLA LOAD DAL DISCO ***/");
		System.out.println(epkPreload);
		System.out.println(eskPreload);
		System.out.println(spkPreload);
		System.out.println(sskPreload);
		System.out.println(aesPreload);
		System.out.println(desedePreload);

		// Salvo sul disco il KeyRing privato
		skr.store(new FileOutputStream(new File("privateKeyRing.bin")), "paperino".toCharArray());

		// Carico il KeyRing privato dal disco
		skr.load(new FileInputStream(new File("privateKeyRing.bin")), "paperino".toCharArray());

		String epkPostload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_EPK").getEncoded());
		String eskPostload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_ESK").getEncoded());
		String spkPostload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_SPK").getEncoded());
		String sskPostload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_SSK").getEncoded());
		String aesPostload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_AES").getEncoded());
		String desedePostload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_DESede").getEncoded());

		System.out.println("\n/*** CHIAVI DOPO LA LOAD DAL DISCO ***/");
		System.out.println(epkPostload);
		System.out.println(eskPostload);
		System.out.println(spkPostload);
		System.out.println(sskPostload);
		System.out.println(aesPostload);
		System.out.println(desedePostload);

		if (epkPreload.equals(epkPostload) && eskPreload.equals(eskPostload) && spkPreload.equals(spkPostload)
				&& sskPreload.equals(sskPostload) && aesPreload.equals(aesPostload)
				&& desedePreload.equals(desedePostload))
			System.out.println(
					"\nLe chiavi recuperate dal disco sono identiche alle chiavi presenti nel KeyRing prima del salvataggio");

		/*************************************************************************************************
		 ******************************* GESTIONE DEL KEYRING PUBBLICO ***********************************
		 ************************************************************************************************/
		PublicKeyRing pkr = PublicKeyRing.getInstance();

		// Gruppo Ancora
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		byte[] encodedKey = Base64.getDecoder().decode(
				"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC87UbZBsXHzim7q/b0nndJpabIHJy21kFu3KHwYoNGUSYO8FO3a4mBQJ7itDh6K/IoQS2DTp5NNyEr+0uRzE1RuTbWHpY24U/dRhkvju2KnZPFA64tdr1s6d07t3LHaMPApY1Rn5YOl0myS/aJRDCxRUiF6TL8C92GTf9nxSfUpwIDAQAB");
		PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
		pkr.setKey("Ancora_EPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

		keyFactory = KeyFactory.getInstance("DSA");
		encodedKey = Base64.getDecoder().decode(
				"MIIBtzCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYQAAoGAGDCs+acIrdVF/aBdADLb6rOHDyAs3/WFTuk8Bx7KY5PQhAgl+6cazxkwqZHM1DJR23pFCFEkj23+V3fUufCTPj++d9NFYMNEuv82ZoBMML2uvlQb4lCNK+WpPez5d6jOkfe7P4aHJjAmIH9JBEs4Gi0NHdfbut6MQ+Wfw8pEzVs=");
		publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
		pkr.setKey("Ancora_SPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

		// Gruppo Linneo
		keyFactory = KeyFactory.getInstance("RSA");
		encodedKey = Base64.getDecoder().decode(
				"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbEoRGFuU3gw/1KYbgA05jANDgarKagEWlJblKnZ3AXlC00GetN9Evo6G4bo3z+r2eSlUaqFFJjTmiZgzb2fGHVFXoy9FyULV+HcOsWE6bJs/chYJ8hf78SxxCpqfBs9lj/vju2XoqTtizlDIx6ofuWq3LS58yDmLBNj2QWuVszQIDAQAB");
		publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
		pkr.setKey("Linneo_EPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

		keyFactory = KeyFactory.getInstance("DSA");
		encodedKey = Base64.getDecoder().decode(
				"MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYUAAoGBANt+1c3mtZRGRP9xztdTKBZQhCGnsLbTIda4uAwKmstFOx53YsrQjG0c0kezdiH+NR3ER2y318pMUyRfEzCeS7rVQ2Pf6MOBbpqOHE9gaCDB4J0mLHVG2sQnjA+p7+smwtclsVEqJljq2/zW3E22Zf7lWLJatLbxp9UJDpgXEnt6");
		publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
		pkr.setKey("Linneo_SPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

		pkr.store(new FileOutputStream(new File("publicKeyRing.bin")));
	}

}
