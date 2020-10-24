import java.math.BigInteger;
import java.security.MessageDigest;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.params.MainNetParams;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

/**
 * @author @javiervargas
 */
public class BitcoinAddress {

	 private static final NetworkParameters NET_PARAMS = MainNetParams.get();
	 static NetworkParameters params = MainNetParams.get();
	

    public static void main(String[] args) throws Exception {
    	
        // Paso 0: Inicializar el servicio proveedor de seguridad.
        java.security.Security.addProvider(new BouncyCastleProvider());
        // Paso 1: Generar el par de claves ECDSA 
        BigInteger privKey = Keys.createEcKeyPair().getPrivateKey();
        BigInteger pubKey = Sign.publicKeyFromPrivate(privKey);
        ECKeyPair keyPair = new ECKeyPair(privKey, pubKey);
        
        AddressGenerator generator = new AddressGenerator("r4", params);
        ECKey key = generator.generate();

        System.out.println("***********************************************");
        System.out.println("Address from private key is: " + LegacyAddress.fromKey(params, key).toString());
        System.out.println("Private Key: " + key.getPrivKey());
        System.out.println("Private Key (HEX): " + key.getPrivateKeyAsHex());
        System.out.println("Private Key (WIF): " + key.getPrivateKeyAsWiF(params));
        System.out.println("***********************************************");

        System.out.println("Private key: " + privKey.toString(16));
        System.out.println("Private key raw: " + privKey);

        System.out.println("Public key: " + pubKey.toString(16));
        System.out.println("Public key raw: " + pubKey);
        System.out.println("Public key (compressed): " + compressPubKey(pubKey));
        String bcPub = compressPubKey(pubKey);
        
        // Paso 2: Crear el hash 256 de la llave pública.
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] s1 = sha.digest(hexStringToByteArray(bcPub));
        System.out.println("SHA256: " + bytesToHex(s1));

        // Paso 3: Crear el hash 160 del hash256 de la llave pública.
        MessageDigest rmd = MessageDigest.getInstance("RipeMD160");
        byte[] r1 = rmd.digest(s1);
        System.out.println("RIPEMD160: " + bytesToHex(r1));
        
        // Paso 4: Añadir el valor byte al principio que identifica la red.
        byte[] r2 = new byte[r1.length + 1];
        r2[0] = 0;
        for (int i = 0; i < r1.length; i++) {
            r2[i + 1] = r1[i];
        }
        System.out.println("Added network byte: " + bytesToHex(r2));
        // Paso 5: Aplicarle sha256 a la cadena resultante del RIPEMD-160 
        byte[] s2 = sha.digest(r2);
        System.out.println("SHA256: " + bytesToHex(s2));
        // 	Paso 6: Aplicarle sha256 nuevamente al hash resultante del hash256 al RIPEMD-160
        byte[] s3 = sha.digest(s2);
        System.out.println("SHA256: " + bytesToHex(s3));

        byte[] a1 = new byte[25];
        //	Paso 7: Extractar los 4 primeros bytes del último hash256 (checksum) y
        for (int i = 0; i < r2.length; i++) {
            a1[i] = r2[i];
        }
        
        //Paso 8: Concatenarlo al hash extendido del paso 4.
        for (int i = 0; i < 4; i++) {
            a1[21 + i] = s3[i];
        }
        System.out.println("Before Base58 encoding: " + bytesToHex(a1));
        
        // Step 9: Convertir la cadena anterior al formato Base58.
        System.out.println("PubKey hash adr: " + Base58.encode(a1));


        // Crear una dirección P2WPKH (Pay to Witness Public Key Hash)
        byte r3[] = new byte[r1.length + 2];
        for (int i = 2; i < r3.length; i++) {
            r3[i] = r1[i - 2];
        }
        r3[0] = 0x00;
        r3[1] = 0x14;

        byte[] P2WPKHs1 = sha.digest(r3);
        System.out.println("SHA256: " + bytesToHex(P2WPKHs1));

        byte[] P2WPKHr1 = rmd.digest(P2WPKHs1);
        System.out.println("RIPEMD160: " + bytesToHex(P2WPKHr1));

        // Poner al inicio de la dirección el valor 0x05 y al final el checksum.
        byte[] final_P2WPKH = new byte[P2WPKHr1.length + 1];
        for (int i = 1; i < final_P2WPKH.length; i++) {
            final_P2WPKH[i] = P2WPKHr1[i - 1];
        }
        final_P2WPKH[0] = 0x05;

        byte[] checksunbyte = sha.digest(sha.digest(final_P2WPKH));

        byte[] P2WPKH_address = new byte[final_P2WPKH.length + 4];
        for (int i = 0; i < final_P2WPKH.length; i++) {
            P2WPKH_address[i] = final_P2WPKH[i];
        }
        for (int i = 0; i < 4; i++) {
            P2WPKH_address[final_P2WPKH.length + i] = checksunbyte[i];
        }
        // Convertir al formato Base58
        System.out.println("P2WPKH Address: " + Base58.encode(P2WPKH_address));
    }

    private static String bytesToHex(byte[] hashInBytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hashInBytes.length; i++) {
            sb.append(Integer.toString((hashInBytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }

    public static String compressPubKey(BigInteger pubKey) {
        String pubKeyYPrefix = pubKey.testBit(0) ? "03" : "02";
        String pubKeyHex = pubKey.toString(16);
        String pubKeyX = pubKeyHex.substring(0, 64);
        return pubKeyYPrefix + pubKeyX;
    }

    public static byte[] hexStringToByteArray(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(s.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    static private String adjustTo64(String s) {
        switch (s.length()) {
            case 62:
                return "00" + s;
            case 63:
                return "0" + s;
            case 64:
                return s;
            default:
                throw new IllegalArgumentException("not a valid key: " + s);
        }
    }
}
