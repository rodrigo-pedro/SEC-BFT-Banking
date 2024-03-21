import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class CreateKeyStore {

    public static RSAPrivateKey readPrivateKey(File file) throws Exception {
        //String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());


        byte[] encoded = Files.readAllBytes(file.toPath());

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }


    public static void main(String[] args) throws Exception {
        System.out.println(args[0] + " " + args[1] + " " + args[2]);
        String password = args[0], certificatePath = args[1], privateKeyPath = args[2];
        System.out.println(System.getProperties());
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, password.toCharArray());
        //SecretKey
        try (FileOutputStream fos = new FileOutputStream("out.jks")) {
            FileInputStream is = new FileInputStream(certificatePath);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(is);
            X509Certificate[] chain = {certificate};

            ks.setKeyEntry("private", readPrivateKey(new File(privateKeyPath)), password.toCharArray(), chain);

            ks.store(fos, "alentejanomau12".toCharArray());

        }

    }
}
