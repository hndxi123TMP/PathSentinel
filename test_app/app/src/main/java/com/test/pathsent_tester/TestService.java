package com.test.pathsent_tester;

import android.app.Service;
import android.content.ContentValues;
import android.content.Intent;
import android.net.Uri;
import android.os.IBinder;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * TestService - Handles Service ICC patterns and multi-hop ICC flows.
 */
public class TestService extends Service {

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            String action = intent.getAction();

            // Basic Service ICC patterns (paths ICC_1 and ICC_2)
            if ("ACTION_TEST_1".equals(action)) {
                handleServiceTest1(intent);
            } else if ("ACTION_TEST_2".equals(action)) {
                handleServiceTest2(intent);
            }
            // Multi-hop ICC patterns (paths COMPLEX_1 and COMPLEX_2)
            else if ("ACTION_MULTIHOP_1".equals(action)) {
                handleMultiHop1(intent);
            } else if ("ACTION_MULTIHOP_2".equals(action)) {
                handleMultiHop2(intent);
            }
            // Mixed ICC pattern (path COMPLEX_5)
            else if ("ACTION_MIXED_START".equals(action)) {
                handleMixedICC(intent);
            }
        }

        return START_NOT_STICKY;
    }

    /**
     * Handles SERVICE ICC path ICC_1
     * Constraint: action = "ACTION_TEST_1" AND auth_level = "user"
     */
    private void handleServiceTest1(Intent intent) {
        String authLevel = intent.getStringExtra("auth_level");
        String filePath = intent.getStringExtra("file_path");

        if ("user".equals(authLevel) && filePath != null) {
            try {
                FileOutputStream fos = new FileOutputStream(filePath);
                fos.write("service test 1 data".getBytes());  // Target sink
                fos.close();
            } catch (IOException e) {
                // Handle exception
            }
        }
    }

    /**
     * Handles SERVICE ICC path ICC_2
     * Constraint: action = "ACTION_TEST_2" AND auth_level = "admin"
     */
    private void handleServiceTest2(Intent intent) {
        String authLevel = intent.getStringExtra("auth_level");
        String filePath = intent.getStringExtra("file_path");

        if ("admin".equals(authLevel) && filePath != null) {
            try {
                FileOutputStream fos = new FileOutputStream(filePath);
                fos.write("service test 2 data".getBytes());  // Target sink
                fos.close();
            } catch (IOException e) {
                // Handle exception
            }
        }
    }

    /**
     * Handles multi-hop ICC path COMPLEX_1
     * Service -> Broadcast pattern
     */
    private void handleMultiHop1(Intent intent) {
        String nextStep = intent.getStringExtra("next_step");
        if ("broadcast".equals(nextStep)) {
            // Continue to broadcast component
            Intent broadcastIntent = new Intent("ACTION_MULTIHOP_BROADCAST_1");
            broadcastIntent.putExtra("source", "service");
            broadcastIntent.putExtra("multihop_path", ComplexICCTests.SHARED_DATA);
            sendBroadcast(broadcastIntent);
        }
    }

    /**
     * Handles multi-hop ICC path COMPLEX_2
     * Service -> ContentProvider pattern
     */
    private void handleMultiHop2(Intent intent) {
        String nextStep = intent.getStringExtra("next_step");
        if ("provider".equals(nextStep)) {
            // Continue to content provider
            Uri uri = Uri.parse("content://com.test.icc.provider/multihop/step2");
            ContentValues values = new ContentValues();
            values.put("source", "service");
            values.put("multihop_path", ComplexICCTests.SHARED_DATA);
            values.put("content", "multihop step 2");
            getContentResolver().insert(uri, values);
        }
    }

    /**
     * Handles mixed ICC path COMPLEX_5
     * Part 1 of Service -> Provider -> Receiver chain
     */
    private void handleMixedICC(Intent intent) {
        String targetPath = intent.getStringExtra("target_path");
        if (targetPath != null) {
            // Step 1: Service -> Provider
            Uri uri = Uri.parse("content://com.test.icc.provider/mixed/chain");
            ContentValues values = new ContentValues();
            values.put("chain_step", "provider");
            values.put("target_path", targetPath);
            values.put("content", "mixed ICC chain step 1");
            getContentResolver().insert(uri, values);
        }
    }
}