import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class RunReadPacket {

	private final static String groupName = "Foo";
	private final static String sndGroupName = "FrankAbba";

	public static void main(String[] args) {
		// Carico il KeyRing privato dal disco
		PrivateKeyRing skr = PrivateKeyRing.getInstance();
		try {
			skr.load(new FileInputStream(new File("privateKeyRing.enc")), "paperino".toCharArray());
		} catch (ClassNotFoundException | GeneralSecurityException | IOException e) {
			e.printStackTrace();
		}

		// Carico il KeyRing pubblico dal disco
		PublicKeyRing pkr = PublicKeyRing.getInstance();
		try {
			pkr.load(new FileInputStream(new File("publicKeyRing.bin")));
		} catch (ClassNotFoundException | IOException e) {
			e.printStackTrace();
		}

		// Inizializzo lo stream del file da decifrare
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(new File("ToFoo_ENC/" + sndGroupName + "_to_" + groupName + ".txt.enc"));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}

		// Leggo la signature dal pacchetto o dal file .sig
		byte[] sigToVerify = null;
		try {
			sigToVerify = getSignature(fis);
		} catch (IOException e) {
			e.printStackTrace();
		}

		SecretKey AESKey = null;
		try {
			// Ottengo la chiave privata RSA del nostro team per poter decifrare
			// la chiave AES letta dal pacchetto
			PrivateKey fooESK = (PrivateKey) skr.getKey("Foo_ESK");

			// Ottengo la chiave AES dal pacchetto
			AESKey = getAESKeyFromPacket(fis, fooESK);
		} catch (Exception e) {
			e.printStackTrace();
		}

		// Leggo l'IV dal pacchetto
		byte[] IV = new byte[16];
		try {
			fis.read(IV);
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Leggo il messaggio cifrato dal pacchetto, lo decifro con la chiave
		// AES e l'IV, e lo scrivo in chiaro sul disco
		try {
			getMessageFromPacket(fis, AESKey, IV);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IOException e) {
			e.printStackTrace();
		}

		try {
			// Ottengo la chiave pubblica DSA del team mittente per verificare
			// la firma e il dato
			PublicKey sndGroupSPK = (PublicKey) pkr.getKey(sndGroupName + "_SPK");

			// Verifico la firma e il dato firmato
			boolean verifies = verify(sigToVerify, sndGroupSPK);

			System.out.println("Signature verifies: " + verifies);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static byte[] getSignature(FileInputStream fis) throws IOException {
		// Leggo il flag dal pacchetto
		int flag = fis.read();

		// Leggo la firma da verificare dal pacchetto o dal file .sig
		FileInputStream fisSig = null;
		if (flag == 1)
			fisSig = new FileInputStream(new File("ToFoo_ENC/" + sndGroupName + "_" + "signature.sig"));
		else
			fisSig = fis;

		// Leggo i primi due header della firma
		byte header1 = (byte) fisSig.read();
		byte header2 = (byte) fisSig.read();

		// Leggo la firma in base al secondo header: se l'header2 è 44, la
		// signature è lunga 46; se l'header2 è 45, la signature è lunga 47; se
		// l'header2 è 46, la signature è lunga 48
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

		return sigToVerify;
	}

	private static SecretKey getAESKeyFromPacket(FileInputStream fis, PrivateKey fooESK)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException,
			IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		cipher.init(Cipher.DECRYPT_MODE, fooESK);

		// Leggo la chiave AES, cifrata con RSA, dal pacchetto
		byte[] encAESKey = new byte[128];
		fis.read(encAESKey);
		byte[] encodedAESKey = cipher.doFinal(encAESKey);

		// Ottengo la chiave AES
		SecretKey AESKey = new SecretKeySpec(encodedAESKey, "AES");

		return AESKey;
	}

	private static void getMessageFromPacket(FileInputStream fis, SecretKey AESKey, byte[] IV)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException {
		// Inizializzo il cifrario in modalità AES/CBC/PKCS5Padding con la
		// AESKey e l'IV
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, AESKey, new IvParameterSpec(IV));

		// Leggo il messaggio cifrato dal pacchetto e lo scrivo decifrato sul
		// disco
		CipherInputStream cis = new CipherInputStream(fis, cipher);

		FileOutputStream fos = new FileOutputStream(
				new File("ToFoo_DEC/" + sndGroupName + "_to_" + groupName + ".txt"));
		byte[] buffer = new byte[1024];
		int len;
		while ((len = cis.read(buffer)) > 0)
			fos.write(buffer, 0, len);
		cis.close();
		fos.close();
	}

	private static boolean verify(byte[] sigToVerify, PublicKey sndGroupSPK)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {
		// Inizializzo l'oggetto Signature per la verifica
		Signature sig = Signature.getInstance("SHA1WithDSA");
		sig.initVerify(sndGroupSPK);

		// Prelevo i dati che devono essere verificati e li aggiorno col
		// metodo update
		FileInputStream fis = new FileInputStream(new File("ToFoo_DEC/" + sndGroupName + "_to_" + groupName + ".txt"));
		BufferedInputStream bis = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = bis.read(buffer)) > 0)
			sig.update(buffer, 0, len);
		bis.close();

		// Verifico la signature
		boolean verifies = sig.verify(sigToVerify);

		return verifies;
	}

}
