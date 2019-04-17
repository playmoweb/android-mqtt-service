package net.igenius.mqttservice;

import android.content.Context;

import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.HashMap;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * @author Thibaud Giovannetti
 * @date 17/04/2019
 */
class SslUtility {
    private final Context context;
    private final HashMap<Integer, SSLSocketFactory> mSocketFactoryMap = new HashMap<>();

    SslUtility(final Context context) {
        this.context = context;
    }

    SSLSocketFactory getSocketFactory(final int certificateId, final String certificatePassword) {
        SSLSocketFactory result = mSocketFactoryMap.get(certificateId);

        if(result != null){
            return result;
        }

        if (null != context) {
            try {
                final KeyStore keystoreTrust = KeyStore.getInstance("BKS");
                keystoreTrust.load(context.getResources().openRawResource(certificateId), certificatePassword.toCharArray());
                final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(keystoreTrust);

                final SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());

                result = sslContext.getSocketFactory();
                mSocketFactoryMap.put(certificateId, result);
            } catch (final Exception ex) {
                MQTTServiceLogger.error("Socket Factory Error", ex.getMessage());
            }
        }

        return result;
    }
}
