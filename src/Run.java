public class Run {

	public static void main(String[] args) throws Exception {
		PrivateKeyRing pkr = PrivateKeyRing.getInstance();
		System.out.println(pkr.getKey("I2X3_EPK").getEncoded());
	}

}
