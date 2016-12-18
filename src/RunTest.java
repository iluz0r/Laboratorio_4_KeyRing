import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
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

public class RunTest {

	private final static String groupName = "Foo";
	private final static String recvGroupName = "MakeNao";
	private final static String sndGroupName = "MakeNao";

	public static void main(String[] args) throws Exception {
		// Carico il KeyRing privato dal disco
		PrivateKeyRing skr = PrivateKeyRing.getInstance();
		skr.load(new FileInputStream(new File("privateKeyRing.enc")), "paperino".toCharArray());
		
		// Carico il KeyRing pubblico dal disco
		PublicKeyRing pkr = PublicKeyRing.getInstance();
		pkr.load(new FileInputStream(new File("publicKeyRing.bin")));

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

		fos = new FileOutputStream(new File(groupName + "_to_" + recvGroupName + ".txt.enc"));
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
		fos = new FileOutputStream(new File(groupName + "_to_" + recvGroupName + ".txt.enc"), true);
		CipherOutputStream cos = new CipherOutputStream(fos, cipher);
		cos.write(AESKey.getEncoded());
		cos.close();

		// Ottengo una istanza del cipher e lo inizializzo
		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, AESKey);

		// Salvo l'IV sul file
		fos = new FileOutputStream(new File(groupName + "_to_" + recvGroupName + ".txt.enc"), true);
		fos.write(cipher.getIV());
		fos.close();

		// Leggo il file in chiaro e lo cifro con AES/CBC/PKCS5Padding con
		// AESKey scrivendolo sul file
		fis = new FileInputStream(new File("file.txt"));
		bis = new BufferedInputStream(fis);
		fos = new FileOutputStream(new File(groupName + "_to_" + recvGroupName + ".txt.enc"), true);
		cos = new CipherOutputStream(fos, cipher);
		buffer = new byte[1024];

		while ((len = bis.read(buffer)) >= 0)
			cos.write(buffer, 0, len);
		bis.close();
		cos.close();

		// Testing: lettura del file ricevuto dal team Ancora
		fis = new FileInputStream(new File("ToFoo_ENC/" + sndGroupName + "_to_" + groupName + ".txt.enc"));
		int flag = fis.read();

		FileInputStream fisSig = null;
		if (flag == 1)
			fisSig = new FileInputStream(new File("ToFoo_ENC/" + "signature.sig"));
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
		fos = new FileOutputStream(new File("ToFoo_DEC/" + sndGroupName + "_to_" + groupName + ".txt"));

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
		fis = new FileInputStream(new File("ToFoo_DEC/" + sndGroupName + "_to_" + groupName + ".txt"));
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