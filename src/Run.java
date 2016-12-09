import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class Run {

	private static final String groupName = "I2X3";
	
	public static void main(String[] args) throws Exception {
		PrivateKeyRing pkr = PrivateKeyRing.getInstance();

		KeyPair RSAKeyPair, DSAKeyPair;
		KeyPairGenerator RSAKeyPairGen = KeyPairGenerator.getInstance("RSA");
		RSAKeyPairGen.initialize(1024);
		RSAKeyPair = RSAKeyPairGen.genKeyPair();

		KeyPairGenerator DSAKeyPairGen = KeyPairGenerator.getInstance("DSA");
		DSAKeyPairGen.initialize(1024);
		DSAKeyPair = DSAKeyPairGen.genKeyPair();

		// EPK = public encryption key
		pkr.setKey(groupName + "_EPK", RSAKeyPair.getPublic(), "EPK");
		// ESK = private decryption key
		pkr.setKey(groupName + "_ESK", RSAKeyPair.getPrivate(), "ESK");
		// SPK = public verification key
		pkr.setKey(groupName + "_SPK", DSAKeyPair.getPublic(), "SPK");
		// SSK = private signing key
		pkr.setKey(groupName + "_SSK", DSAKeyPair.getPrivate(), "SSK");
		
		System.out.println(pkr.getKey(groupName + "_EPK"));
	}

}
