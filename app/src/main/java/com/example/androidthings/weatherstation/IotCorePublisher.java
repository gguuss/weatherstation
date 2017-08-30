/*
 * Copyright 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.androidthings.weatherstation;

import android.content.Context;
import android.content.res.Resources;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;

import org.eclipse.paho.client.mqttv3.MqttException;
import org.json.JSONException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;
import org.joda.time.DateTime;

import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;

// TODO(class): move to a service class.
class IotCorePublisher {
    private static final String TAG = IotCorePublisher.class.getSimpleName();

    private final Context mContext;
    private final String mAppname;
    private final String mTopic;

    private Handler mHandler;
    private HandlerThread mHandlerThread;

    private float mLastTemperature = Float.NaN;
    private float mLastPressure = Float.NaN;

    private static String mProjectId;
    private static String mGcloudRegion;
    private static String mRegistryId;
    private static String mDeviceId;

    MqttClient mClient;

    private static final long PUBLISH_INTERVAL_MS = TimeUnit.MINUTES.toMillis(1);

    /** Create a Cloud IoT Core JWT for the given project id, signed with the given private key. */
    private static String createJwtRsa(String projectId, Context mContext, int credentialResourceId)
            throws Exception {
        DateTime now = new DateTime();
        // Create a JWT to authenticate this device. The device will be disconnected after the token
        // expires, and will have to reconnect with a new token. The audience field should always be set
        // to the GCP project id.
        JwtBuilder jwtBuilder =
                Jwts.builder()
                        .setIssuedAt(now.toDate())
                        .setExpiration(now.plusMinutes(20).toDate())
                        .setAudience(projectId);

        InputStream privateKey = mContext.getResources().openRawResource(credentialResourceId);
        byte[] keyBytes = inputStreamToBytes(privateKey);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        return jwtBuilder.signWith(SignatureAlgorithm.RS256, kf.generatePrivate(spec)).compact();
    }

    private static String createJwtEs(String projectId, Context mContext, int credentialResourceId)
            throws Exception {
        DateTime now = new DateTime();
        // Create a JWT to authenticate this device. The device will be disconnected after the token
        // expires, and will have to reconnect with a new token. The audience field should always be set
        // to the GCP project id.
        JwtBuilder jwtBuilder =
                Jwts.builder()
                        .setIssuedAt(now.toDate())
                        .setExpiration(now.plusMinutes(20).toDate())
                        .setAudience(projectId);

        InputStream privateKey = mContext.getResources().openRawResource(credentialResourceId);
        byte[] keyBytes = inputStreamToBytes(privateKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC");

        return jwtBuilder.signWith(SignatureAlgorithm.ES256, kf.generatePrivate(spec)).compact();
    }

    private static byte[] inputStreamToBytes(InputStream is) throws IOException{
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        int nRead;
        byte[] data = new byte[16384];

        while ((nRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }

        buffer.flush();

        return buffer.toByteArray();
    }

    IotCorePublisher(Context context, String appname, String project, String topic,
                     int credentialResourceId) throws Exception {
        mContext = context;
        mAppname = appname;
        mTopic = "projects/" + project + "/topics/" + topic;

        mHandlerThread = new HandlerThread("iotCorePublisherThread");
        mHandlerThread.start();
        mHandler = new Handler(mHandlerThread.getLooper());

        // For Cloud IoT Core resource strings
        Resources res = context.getResources();

        // TODO: Init here
        // TODO: Separate message send block
        // If you have issues with port 8883, you can use 443
        String mqttServerAddress =
                String.format("ssl://%s:%s", "mqtt.googleapis.com", 8883);

        // Load Cloud IoT Core configuration parameters from string resources.
        mProjectId = res.getString(R.string.gcloud_project_id);
        mGcloudRegion = res.getString(R.string.gcloud_region);
        mRegistryId = res.getString(R.string.iot_core_registry_id);
        mDeviceId = res.getString(R.string.iot_core_device_id);

        // Create our MQTT client. The mqttClientId is a unique string that identifies this device. For
        // Google Cloud IoT Core, it must be in the format below.
        String mqttClientId =
                String.format(
                        "projects/%s/locations/%s/registries/%s/devices/%s",
                        mProjectId, mGcloudRegion, mRegistryId, mDeviceId);

        MqttConnectOptions connectOptions = new MqttConnectOptions();
        // Note that the the Google Cloud IoT Core only supports MQTT 3.1.1, and Paho requires that we
        // explictly set this. If you don't set MQTT version, the server will immediately close its
        // connection to your device.
        connectOptions.setMqttVersion(MqttConnectOptions.MQTT_VERSION_3_1_1);

        // With Google Cloud IoT Core, the username field is ignored, however it must be set for the
        // Paho client library to send the password field. The password field is used to transmit a JWT
        // to authorize the device.
        connectOptions.setUserName("unused");

        // Currently, just calculate the JWT using RSA.
        connectOptions.setPassword(
                createJwtRsa(mProjectId, context, credentialResourceId).toCharArray());

        // Create a client, and connect to the Google MQTT bridge.
        mClient = new MqttClient(mqttServerAddress, mqttClientId, new MemoryPersistence());
        mClient.connect(connectOptions);

        mHandler.post(new Runnable() {
            @Override
            public void run() {

            }
        });
    }

    public void start() {
        mHandler.post(mIotCoreRunnable);
    }

    public void stop() {
        mHandler.removeCallbacks(mIotCoreRunnable);
    }

    public void close() {
        mHandler.removeCallbacks(mIotCoreRunnable);
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                try {
                    mClient.disconnect();
                } catch (MqttException e) {
                    Log.d(TAG, "error disconnecting MQTT");
                } finally {
                    mClient = null;
                }
            }
        });
        mHandlerThread.quitSafely();
    }

    public SensorEventListener getTemperatureListener() {
        return mTemperatureListener;
    }

    public SensorEventListener getPressureListener() {
        return mPressureListener;
    }

    private Runnable mIotCoreRunnable = new Runnable() {
        @Override
        public void run() {
            ConnectivityManager connectivityManager =
                    (ConnectivityManager) mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
            NetworkInfo activeNetwork = connectivityManager.getActiveNetworkInfo();
            if (activeNetwork == null || !activeNetwork.isConnectedOrConnecting()) {
                Log.e(TAG, "no active network");
                return;
            }

            try {
                String payload = createMessagePayload(mLastTemperature, mLastPressure);
                Log.d(TAG, "publishing message: " + payload);
                String mqttTopic = String.format("/devices/%s/events", mDeviceId);

                // Publish "payload" to the MQTT topic. qos=1 means at least once delivery. Cloud IoT Core
                // also supports qos=0 for at most once delivery.
                if (payload.getBytes().length > 0) {
                    MqttMessage message = new MqttMessage(payload.getBytes());
                    message.setQos(1);
                    mClient.publish(mqttTopic, message);
                } else {
                    Log.d(TAG, "Did not publish empty message");
                }
            } catch (JSONException | MqttException e) {
                Log.e(TAG, "Error publishing message", e);
            } finally {
                mHandler.postDelayed(mIotCoreRunnable, PUBLISH_INTERVAL_MS);
            }
        }

        private String createMessagePayload(float temperature, float pressure)
                throws JSONException {
            if (Float.isNaN(temperature) || Float.isNaN(pressure)) {
                return "";
            }
            return String.format("%s/%s-temp-%.2f-press-%.2f", mRegistryId, mDeviceId,
                    temperature, pressure);
        }
    };

    private SensorEventListener mTemperatureListener = new SensorEventListener() {
        @Override
        public void onSensorChanged(SensorEvent event) {
            mLastTemperature = event.values[0];
        }

        @Override
        public void onAccuracyChanged(Sensor sensor, int accuracy) {}
    };

    private SensorEventListener mPressureListener = new SensorEventListener() {
        @Override
        public void onSensorChanged(SensorEvent event) {
            mLastPressure = event.values[0];
        }

        @Override
        public void onAccuracyChanged(Sensor sensor, int accuracy) {}
    };
}