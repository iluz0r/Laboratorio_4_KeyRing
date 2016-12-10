import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.ArrayList;

public class PublicKeyRing extends KeyRing {

	private static PublicKeyRing instance = null;

	private PublicKeyRing() {
		super();
	}

	public static PublicKeyRing getInstance() {
		if (instance == null)
			instance = new PublicKeyRing();
		return instance;
	}

	public void load(InputStream is) throws IOException, ClassNotFoundException {
		ObjectInputStream ois = new ObjectInputStream(is);
		keyRing = (ArrayList<Record>) ois.readObject();

		ois.close();
	}

	public void store(OutputStream os) throws IOException {
		ObjectOutputStream oos = new ObjectOutputStream(os);
		oos.writeObject(keyRing);

		oos.close();
	}

}
