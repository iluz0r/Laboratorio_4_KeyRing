import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
//import java.security.Key;
import java.security.KeyFactory;
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Run {

	private final static String groupName = "Foo";
	private final static String recvGroupName = "DomenicoM";
	private final static String sndGroupName = "Doriana";

	public static void main(String[] args) throws Exception {
		/*************************************************************************************************
		 ******************************* GESTIONE DEL KEYRING PRIVATO ************************************
		 ************************************************************************************************/
		PrivateKeyRing skr = PrivateKeyRing.getInstance();

		// // Genero la coppia di chiavi RSA per cifrare/decifrare
		// KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		// keyPairGen.initialize(1024);
		// KeyPair RSAKeyPair = keyPairGen.genKeyPair();
		//
		// // Genero la coppia di chiavi DSA per firmare/verificare
		// keyPairGen = KeyPairGenerator.getInstance("DSA");
		// keyPairGen.initialize(1024);
		// KeyPair DSAKeyPair = keyPairGen.genKeyPair();
		//
		// // Inserisco le coppie di chiavi generate (RSA e DSA) nel mazzo di
		// // chiavi privato
		// Key key = RSAKeyPair.getPublic();
		// // EPK = public encryption key
		// skr.setKey(groupName + "_EPK", key, key.getAlgorithm() + "/" +
		// key.getFormat());
		//
		// key = RSAKeyPair.getPrivate();
		// // ESK = private decryption key
		// skr.setKey(groupName + "_ESK", key, key.getAlgorithm() + "/" +
		// key.getFormat());
		//
		// key = DSAKeyPair.getPublic();
		// // SPK = public verification key
		// skr.setKey(groupName + "_SPK", key, key.getAlgorithm() + "/" +
		// key.getFormat());
		//
		// key = DSAKeyPair.getPrivate();
		// // SSK = private signing key
		// skr.setKey(groupName + "_SSK", key, key.getAlgorithm() + "/" +
		// key.getFormat());
		//
		// // Genero una chiave AES a 128 bit
		// KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		// keyGen.init(128);
		// SecretKey AESKey = keyGen.generateKey();
		//
		// // Genero una chiave DESede a 168 bit
		// keyGen = KeyGenerator.getInstance("DESede");
		// keyGen.init(168);
		// SecretKey DESedeKey = keyGen.generateKey();
		//
		// // Inserisco le chiavi AES e DESede nel mazzo di chiavi privato
		// skr.setKey(groupName + "_AES", AESKey, AESKey.getAlgorithm() + "/" +
		// AESKey.getFormat());
		// skr.setKey(groupName + "_DESede", DESedeKey, DESedeKey.getAlgorithm()
		// + "/" + DESedeKey.getFormat());
		//
		// // Ottengo le chiavi del KeyRing privato e le stampo a video in
		// base64
		// String epkPreload =
		// Base64.getEncoder().encodeToString(skr.getKey(groupName +
		// "_EPK").getEncoded());
		// String eskPreload =
		// Base64.getEncoder().encodeToString(skr.getKey(groupName +
		// "_ESK").getEncoded());
		// String spkPreload =
		// Base64.getEncoder().encodeToString(skr.getKey(groupName +
		// "_SPK").getEncoded());
		// String sskPreload =
		// Base64.getEncoder().encodeToString(skr.getKey(groupName +
		// "_SSK").getEncoded());
		// String aesPreload =
		// Base64.getEncoder().encodeToString(skr.getKey(groupName +
		// "_AES").getEncoded());
		// String desedePreload =
		// Base64.getEncoder().encodeToString(skr.getKey(groupName +
		// "_DESede").getEncoded());
		//
		// System.out.println("/*** CHIAVI PRIMA DELLA LOAD DAL DISCO ***/");
		// System.out.println(epkPreload);
		// System.out.println(eskPreload);
		// System.out.println(spkPreload);
		// System.out.println(sskPreload);
		// System.out.println(aesPreload);
		// System.out.println(desedePreload);
		//
		// // Salvo sul disco il KeyRing privato
		// skr.store(new FileOutputStream(new File("privateKeyRing.bin")),
		// "paperino".toCharArray());

		// Carico il KeyRing privato dal disco
		skr.load(new FileInputStream(new File("privateKeyRing.bin")), "paperino".toCharArray());

		String epkPostload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_EPK").getEncoded());
		String eskPostload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_ESK").getEncoded());
		String spkPostload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_SPK").getEncoded());
		String sskPostload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_SSK").getEncoded());
		String aesPostload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_AES").getEncoded());
		String desedePostload = Base64.getEncoder().encodeToString(skr.getKey(groupName + "_DESede").getEncoded());

		System.out.println("/*** CHIAVI DOPO LA LOAD DAL DISCO ***/");
		System.out.println("Foo_EPK: " + epkPostload);
		System.out.println("Foo_ESK: " + eskPostload);
		System.out.println("Foo_SPK: " + spkPostload);
		System.out.println("Foo_SSK: " + sskPostload);
		System.out.println("Foo_AES: " + aesPostload);
		System.out.println("Foo_DESede: " + desedePostload);

		// if (epkPreload.equals(epkPostload) && eskPreload.equals(eskPostload)
		// && spkPreload.equals(spkPostload)
		// && sskPreload.equals(sskPostload) && aesPreload.equals(aesPostload)
		// && desedePreload.equals(desedePostload))
		// System.out.println(
		// "\nLe chiavi recuperate dal disco sono identiche alle chiavi presenti
		// nel KeyRing prima del salvataggio");

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

		// Gruppo DomenicoM
		keyFactory = KeyFactory.getInstance("RSA");
		encodedKey = Base64.getDecoder().decode(
				"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4+irxZi0XX6qqDYT+eJGYP+7QI78ecC8qntniGboBv8VO2Uwcm3gvfc/ufg7O12GmWgxG+cCNQNtY2hKiKa5+ZPLxLka1AxbQzyYynUoePWQa8wxklqPKYg389ywPJ+E+L8hxcTQE3wPPFujKNOvqG2U70EXqXzYITjzZjkLnmwIDAQAB");
		publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
		pkr.setKey("DomenicoM_EPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

		keyFactory = KeyFactory.getInstance("DSA");
		encodedKey = Base64.getDecoder().decode(
				"MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYUAAoGBAITTzEdbcjEj1NzhOv+JUWWXVz+Y+2sFV5xHoZ/M1bAypsI0Vq1T+kJFVzd3It0PAfwcBCjgI5yrvZlq72GJa3n22AHQoD6C3xTDOFq23FxtDncM6EXuXIkF25JRQD21TNQniN6XTMZqSsQlGtPOmc4AybAIzIY90rxHgBeLxxIZ");
		publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
		pkr.setKey("DomenicoM_SPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

		// Gruppo Doriana
		keyFactory = KeyFactory.getInstance("RSA");
		encodedKey = Base64.getDecoder().decode(
				"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCKLSv1g+DJoaXlwnRMngt+Q9I4SRutTjrbY7JhSXNV2JcBWR9/cKbhrivbOoqVWQnfUjkRPJLZQfORoGI1YmNXrspxVQ7v75ZLn6lWjWd4QklzaayVW74RgN1HRnyU66iPikCTXMT9FkvIg+wh4IHX4afavQjg1dl6BIXnhUYoYQIDAQAB");
		publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
		pkr.setKey("Doriana_EPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

		keyFactory = KeyFactory.getInstance("DSA");
		encodedKey = Base64.getDecoder().decode(
				"MIIBtzCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYQAAoGAHqFhTzkF8cV7D33wPwqBbYvhj72NG8yz3LMGVhNlQndliOavVMJiXG6K2wTjpOISES3ry7Ck+AkmWwhLoP0BST2+s+uxJM25wBly63DWKQ+LgJejNocL3BVnTtPtchPgCzVc43tYvrCt3+9NwFNlw9OUH+VuDTXKi0FCXVNHfvo=");
		publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
		pkr.setKey("Doriana_SPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

		// Gruppo IPini
		keyFactory = KeyFactory.getInstance("RSA");
		encodedKey = Base64.getDecoder().decode(
				"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDudrQ9SD1QgI8dZqmz0DUDO3cGdvd/SclrnJqTcn0qPuxKz9doGjfFB9SxkWnr3JDc8ooLgg9lMxRdjunGTqt2Wk2COqBLiC7d+ZOkiGfae4icHgWngYSdtQ+RW8K+bTpMlyneaXiQvE8l/w35I1DAHz08gEvEzMZt3+v3nRLEdwIDAQAB");
		publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
		pkr.setKey("IPini_EPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

		keyFactory = KeyFactory.getInstance("DSA");
		encodedKey = Base64.getDecoder().decode(
				"MIIBtzCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYQAAoGAQRrs90eRKYJnmht3epyBR2lb5/Hg/mEJUMjuic80XIIZx74YO0pLSnAa9lg9QMWdeZVQYO0zB4JfBU5UidEesOhmKYX8MBUk+on5eRirO2P6zeQ0xxnmaCUGgL4vaoSodG1NNq/TFBmhpuVUYrtgirjzK2EJ8NDFrieDEI4Wjl8=");
		publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
		pkr.setKey("IPini_SPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

		// Salvo sul disco il KeyRing pubblico
		pkr.store(new FileOutputStream(new File("publicKeyRing.bin")));

		/*************************************************************************************************
		 ************************************* GESTIONE DEL TESTING **************************************
		 ************************************************************************************************/
		// Calcolo la data corrente nel formato dd/mm/yyyy
		Date date = Calendar.getInstance().getTime();
		DateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
		String today = formatter.format(date);

		// Genero un nonce di 20 byte
		byte[] nonce = new byte[20];
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(nonce);

		// Scrivo il file da scambiare (in chiaro) sul disco
		FileOutputStream fos = new FileOutputStream(new File("file.txt"));
		BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(fos, "UTF-8"));
		bw.write("**********************************************" + System.getProperty("line.separator"));
		bw.write("* Laurea Magistrale in Ingegneria Informatica" + System.getProperty("line.separator"));
		bw.write("* Corso di Sicurezza Informatica" + System.getProperty("line.separator"));
		bw.write("* Messaggio del " + today + System.getProperty("line.separator"));
		bw.write("* Dal gruppo: Foo" + System.getProperty("line.separator"));
		bw.write("* Al gruppo: " + recvGroupName + System.getProperty("line.separator"));
		bw.write("* Nonce: " + Base64.getEncoder().encodeToString(nonce) + System.getProperty("line.separator"));
		bw.write("**********************************************");
		bw.close();

		// Ottengo una istanza di Signature e la inizializzo con la Foo_SSK
		Signature sig = Signature.getInstance("SHA1withDSA");
		PrivateKey fooSSK = (PrivateKey) skr.getKey("Foo_SSK");
		sig.initSign(fooSSK);

		// Prelevo i dati che devono essere firmati e li aggiorno con il metodo
		// update
		FileInputStream fis = new FileInputStream(new File("file.txt"));
		BufferedInputStream bis = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = bis.read(buffer)) >= 0)
			sig.update(buffer, 0, len);
		bis.close();

		// Firmo i dati ottenendo la signature e la salvo sul disco (come
		// object) assieme al flag
		byte[] signature = sig.sign();

		fos = new FileOutputStream(new File(groupName + "_to_" + recvGroupName + ".bin"));
		fos.write(0x00);
		fos.write(signature);

		// Genero una chiave AES a 128 bit
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey AESKey = keyGen.generateKey();

		// Recupero dal PublicKeyRing la EPK del team Ancora e inizializzo il
		// cifrario in modalità RSA con questa chiave
		PublicKey recvGroupEPK = (PublicKey) pkr.getKey(recvGroupName + "_EPK");
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, recvGroupEPK);

		// Salvo sul file la chiave (opaca) AES generata in precedenza,
		// cifrandola con RSA (con chiave pubblica del team Ancora)
		fos = new FileOutputStream(new File(groupName + "_to_" + recvGroupName + ".bin"), true);
		CipherOutputStream cos = new CipherOutputStream(fos, cipher);
		cos.write(AESKey.getEncoded());
		cos.close();

		// Ottengo una istanza del cipher e lo inizializzo
		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, AESKey);

		// Salvo l'IV sul file
		fos = new FileOutputStream(new File(groupName + "_to_" + recvGroupName + ".bin"), true);
		fos.write(cipher.getIV());
		fos.close();

		// Leggo il file in chiaro e lo cifro con AES/CBC/PKCS5Padding con
		// AESKey scrivendolo sul file
		fis = new FileInputStream(new File("file.txt"));
		bis = new BufferedInputStream(fis);
		fos = new FileOutputStream(new File(groupName + "_to_" + recvGroupName + ".bin"), true);
		cos = new CipherOutputStream(fos, cipher);
		buffer = new byte[1024];

		while ((len = bis.read(buffer)) >= 0)
			cos.write(buffer, 0, len);
		bis.close();
		cos.close();

		// Testing: lettura del file ricevuto dal team Ancora
		fis = new FileInputStream(new File(sndGroupName + "_to_" + groupName + ".bin"));
		int flag = fis.read();

		FileInputStream fisSig = null;
		if (flag == 1)
			fisSig = new FileInputStream(new File("signature.sig"));
		else
			fisSig = fis;

		// Leggo i primi due header della firma
		byte header1 = (byte) fisSig.read();
		byte header2 = (byte) fisSig.read();

		// Leggo la firma in base al secondo header
		byte[] sigToVerify = null;
		
		if (header2 == 44) {
			sigToVerify = new byte[46];
			fisSig.read(sigToVerify, 2, 44);
		}
		if (header2 == 45) {
			sigToVerify = new byte[47];
			fisSig.read(sigToVerify, 2, 45);
		}
		if (header2 == 46) {
			sigToVerify = new byte[48];
			fisSig.read(sigToVerify, 2, 46);
		}
		sigToVerify[0] = header1;
		sigToVerify[1] = header2;

		PrivateKey fooESK = (PrivateKey) skr.getKey("Foo_ESK");
		cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		cipher.init(Cipher.DECRYPT_MODE, fooESK);

		// La chiave AES è a 128 bit (16 bytes) tuttavia essendo cifrata con RSA
		// è lunga 128 bytes
		byte[] AESKeyCiphered = new byte[128];
		fis.read(AESKeyCiphered);
		byte[] AESKeyBytes = cipher.doFinal(AESKeyCiphered);

		// Ottengo la SecretKey AES a partire dal vettore di byte
		AESKey = new SecretKeySpec(AESKeyBytes, "AES");

		// Ottengo l'IV
		byte[] IV = new byte[16];
		fis.read(IV);

		// Inizializzo il cifrario in modalità AES/CBC/PKCS5Padding con la
		// AESKey e l'IV
		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, AESKey, new IvParameterSpec(IV));

		// Leggo il File cifrato dal messaggio e lo scrivo decifrato nel file
		// testDecrypted.txt
		CipherInputStream cis = new CipherInputStream(fis, cipher);
		fos = new FileOutputStream(new File("fileDecrypted.txt"));

		buffer = new byte[1024];
		while ((len = cis.read(buffer)) > 0)
			fos.write(buffer, 0, len);
		cis.close();
		fos.close();

		// Ottengo la chiave pubblica DSA del team Ancora
		PublicKey sndGroupSPK = (PublicKey) pkr.getKey(sndGroupName + "_SPK");

		// Inizializzo l'oggetto Signature per la verifica della signature
		sig = Signature.getInstance("SHA1WithDSA");
		sig.initVerify(sndGroupSPK);

		// Prelevo i dati che devono essere verificati e li aggiorno col
		// metodo update
		fis = new FileInputStream(new File("fileDecrypted.txt"));
		bis = new BufferedInputStream(fis);

		buffer = new byte[1024];
		while ((len = bis.read(buffer)) > 0)
			sig.update(buffer, 0, len);
		bis.close();

		// Verifico la signature
		boolean verifies = sig.verify(sigToVerify);
		System.out.println("Signature verifies: " + verifies);
	}

}