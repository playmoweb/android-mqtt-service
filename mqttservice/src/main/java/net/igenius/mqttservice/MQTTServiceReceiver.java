package net.igenius.mqttservice;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;

import static net.igenius.mqttservice.MQTTServiceCommand.BROADCAST_CONNECTION_SUCCESS;
import static net.igenius.mqttservice.MQTTServiceCommand.BROADCAST_EXCEPTION;
import static net.igenius.mqttservice.MQTTServiceCommand.BROADCAST_MESSAGE_ARRIVED;
import static net.igenius.mqttservice.MQTTServiceCommand.BROADCAST_SUBSCRIPTION_SUCCESS;
import static net.igenius.mqttservice.MQTTServiceCommand.PARAM_BROADCAST_TYPE;
import static net.igenius.mqttservice.MQTTServiceCommand.PARAM_EXCEPTION;
import static net.igenius.mqttservice.MQTTServiceCommand.PARAM_PAYLOAD;
import static net.igenius.mqttservice.MQTTServiceCommand.PARAM_REQUEST_ID;
import static net.igenius.mqttservice.MQTTServiceCommand.PARAM_TOPIC;
import static net.igenius.mqttservice.MQTTServiceCommand.getBroadcastAction;

/**
 * Created by Aleksandar Gotev (aleksandar@igenius.net) on 16/01/17.
 */

public abstract class MQTTServiceReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || intent.getAction() == null
                || !getBroadcastAction().equals(intent.getAction()))
            return;

        String broadcastType = intent.getStringExtra(PARAM_BROADCAST_TYPE);
        String requestId = intent.getStringExtra(PARAM_REQUEST_ID);

        if (broadcastType == null || broadcastType.isEmpty()
                || requestId == null || requestId.isEmpty()) {
            MQTTServiceLogger.error(getClass().getSimpleName(),
                    "received broadcast intent with invalid type and requestId! Discarding it");
            return;
        }

        if (BROADCAST_EXCEPTION.equals(broadcastType)) {
            onException(context, requestId, (Exception) intent.getSerializableExtra(PARAM_EXCEPTION));

        } else if (BROADCAST_CONNECTION_SUCCESS.equals(broadcastType)) {
            onConnectionSuccessful(context, requestId);

        } else if (BROADCAST_MESSAGE_ARRIVED.equals(broadcastType)) {
            onMessageArrived(context, intent.getStringExtra(PARAM_TOPIC),
                             intent.getStringExtra(PARAM_PAYLOAD));

        } else if (BROADCAST_SUBSCRIPTION_SUCCESS.equals(broadcastType)) {
            onSubscriptionSuccessful(context, requestId, intent.getStringExtra(PARAM_TOPIC));
        }
    }

    /**
     * Register this upload receiver.<br>
     * If you use this receiver in an {@link android.app.Activity}, you have to call this method inside
     * {@link android.app.Activity#onResume()}, after {@code super.onResume();}.<br>
     * If you use it in a {@link android.app.Service}, you have to
     * call this method inside {@link android.app.Service#onCreate()}, after {@code super.onCreate();}.
     *
     * @param context context in which to register this receiver
     */
    public void register(final Context context) {
        final IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(getBroadcastAction());
        context.registerReceiver(this, intentFilter);
    }

    /**
     * Unregister this upload receiver.<br>
     * If you use this receiver in an {@link android.app.Activity}, you have to call this method inside
     * {@link android.app.Activity#onPause()}, after {@code super.onPause();}.<br>
     * If you use it in a {@link android.app.Service}, you have to
     * call this method inside {@link android.app.Service#onDestroy()}.
     *
     * @param context context in which to unregister this receiver
     */
    public void unregister(final Context context) {
        context.unregisterReceiver(this);
    }

    public abstract void onSubscriptionSuccessful(Context context, String requestId, String topic);

    public abstract void onMessageArrived(Context context, String topic, String payload);

    public abstract void onConnectionSuccessful(Context context, String requestId);

    public abstract void onException(Context context, String requestId, Exception exception);

}
