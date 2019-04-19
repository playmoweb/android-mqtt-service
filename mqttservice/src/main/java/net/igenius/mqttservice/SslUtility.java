package net.igenius.mqttservice;

import android.content.Context;
import android.support.annotation.RawRes;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * @author Thibaud Giovannetti
 * @date 17/04/2019
 */
class SslUtility {

    public static SSLSocketFactory getSocketFactory(Context context, @RawRes final Integer caCrtFile, final String crtFile, final String keyFile, final String password) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            X509Certificate caCert = getCertificate(context, caCrtFile);
            X509Certificate cert = getCertificate(crtFile);
            FileReader fileReader = new FileReader(keyFile);
            PEMParser parser = new PEMParser(fileReader);
            PEMKeyPair kp = (PEMKeyPair) parser.readObject();

            PrivateKeyInfo info = kp.getPrivateKeyInfo();

            PrivateKey rdKey = new JcaPEMKeyConverter().setProvider("BC").getPrivateKey(info);

            // CA certificate is used to authenticate server
            KeyStore caKs = KeyStore.getInstance(KeyStore.getDefaultType());
            caKs.load(null, null);
            caKs.setCertificateEntry("ca-certificate", caCert);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(caKs);

            // client key and certificates are sent to server so it can authenticate us
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setCertificateEntry("certificate", cert);
            ks.setKeyEntry("private-key", rdKey, password.toCharArray(), new Certificate[]{cert});
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, password.toCharArray());

            // finally, create SSL socket factory
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            return sslContext.getSocketFactory();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    //return certificate
    private static X509Certificate getCertificate(String pemfile) throws Exception {
        X509Certificate cert = null;
        try {
            FileReader reader = new FileReader(pemfile);
            cert = extract(reader);
        } catch (FileNotFoundException e) {
            throw new IOException("Can't find file " + pemfile);
        } catch (Exception e) {
            System.out.println("#Exception :" + e.getMessage());
        }
        return cert;
    }

    private static X509Certificate getCertificate(Context context, Integer pemRawId){
        X509Certificate cert = null;
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(context.getResources().openRawResource(pemRawId)));
            cert = extract(reader);
        } catch (Exception e) {
            System.out.println("#Exception :" + e.getMessage());
        }
        return cert;
    }

    private static X509Certificate extract(Reader reader) throws Exception {
        final PemReader certReader = new PemReader(reader);
        final PemObject certAsPemObject = certReader.readPemObject();

        if (!certAsPemObject.getType().equalsIgnoreCase("CERTIFICATE")) {
            throw new Exception("Certificate file does not contain a certificate but a " + certAsPemObject.getType());
        }
        final byte[] x509Data = certAsPemObject.getContent();
        final CertificateFactory fact = CertificateFactory.getInstance("X509");
        X509Certificate cert = (X509Certificate) fact.generateCertificate(new ByteArrayInputStream(x509Data));
        if (cert == null) {
            throw new Exception("Certificate file does not contain an X509 certificate");
        }
        return cert;
    }

    private KeyPair decodeKeys(byte[] privKeyBits, byte[] pubKeyBits) throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privKeyBits));
        PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubKeyBits));
        return new KeyPair(pubKey, privKey);
    }
}
