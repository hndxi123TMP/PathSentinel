package com.test.pathsent_tester;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * TestBroadcastReceiver - Handles Broadcast ICC patterns.
 */
public class TestBroadcastReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent != null) {
            String action = intent.getAction();

            // Basic Broadcast ICC patterns (paths ICC_3 and ICC_4)
            if ("ACTION_BROADCAST_1".equals(action)) {
                handleBroadcastTest1(intent);
            } else if ("ACTION_BROADCAST_2".equals(action)) {
                handleBroadcastTest2(intent);
            }
            // Static field ICC patterns (paths COMPLEX_3 and COMPLEX_4)
            else if ("ACTION_READ_STATIC_1".equals(action)) {
                handleStaticFieldICC1();
            } else if ("ACTION_READ_STATIC_2".equals(action)) {
                handleStaticFieldICC2();
            }
            // Multi-hop ICC pattern (path COMPLEX_1 continuation)
            else if ("ACTION_MULTIHOP_BROADCAST_1".equals(action)) {
                handleMultiHopBroadcast1(intent);
            }
            // Mixed ICC pattern (final step of COMPLEX_5)
            else if ("ACTION_MIXED_FINAL".equals(action)) {
                handleMixedICCFinal(intent);
            }
        }
    }

    /**
     * Handles BROADCAST ICC path ICC_3
     * Constraint: action = "ACTION_BROADCAST_1"
     */
    private void handleBroadcastTest1(Intent intent) {
        String logData = intent.getStringExtra("log_data");
        String logPath = intent.getStringExtra("log_path");

        if (logData != null && logPath != null) {
            try {
                FileOutputStream fos = new FileOutputStream(logPath);
                fos.write(logData.getBytes());  // Target sink
                fos.close();
            } catch (IOException e) {
                // Handle exception
            }
        }
    }

    /**
     * Handles BROADCAST ICC path ICC_4
     * Constraint: action = "ACTION_BROADCAST_2"
     */
    private void handleBroadcastTest2(Intent intent) {
        String logData = intent.getStringExtra("log_data");
        String logPath = intent.getStringExtra("log_path");

        if (logData != null && logPath != null) {
            try {
                FileOutputStream fos = new FileOutputStream(logPath);
                fos.write(logData.getBytes());  // Target sink
                fos.close();
            } catch (IOException e) {
                // Handle exception
            }
        }
    }

    /**
     * Handles static field ICC path COMPLEX_3
     * Reads from ComplexICCTests.SHARED_DATA
     */
    private void handleStaticFieldICC1() {
        String sharedData = ComplexICCTests.SHARED_DATA;
        if (sharedData != null && sharedData.startsWith("static1_")) {
            try {
                String filePath = "/data/static_field1.log";
                FileOutputStream fos = new FileOutputStream(filePath);
                fos.write(("Static field data: " + sharedData).getBytes());  // Target sink
                fos.close();
            } catch (IOException e) {
                // Handle exception
            }
        }
    }

    /**
     * Handles static field ICC path COMPLEX_4
     * Reads from ComplexICCTests.SHARED_DATA
     */
    private void handleStaticFieldICC2() {
        String sharedData = ComplexICCTests.SHARED_DATA;
        if (sharedData != null && sharedData.startsWith("static2_")) {
            try {
                String filePath = "/data/static_field2.log";
                FileOutputStream fos = new FileOutputStream(filePath);
                fos.write(("Static field data: " + sharedData).getBytes());  // Target sink
                fos.close();
            } catch (IOException e) {
                // Handle exception
            }
        }
    }

    /**
     * Handles multi-hop ICC path COMPLEX_1 (final step)
     * Service -> Broadcast continuation
     */
    private void handleMultiHopBroadcast1(Intent intent) {
        String source = intent.getStringExtra("source");
        String multihopPath = intent.getStringExtra("multihop_path");

        if ("service".equals(source) && multihopPath != null) {
            try {
                FileOutputStream fos = new FileOutputStream(multihopPath);
                fos.write("multihop service->broadcast complete".getBytes());  // Target sink
                fos.close();
            } catch (IOException e) {
                // Handle exception
            }
        }
    }

    /**
     * Handles mixed ICC path COMPLEX_5 (final step)
     * Final step of Service -> Provider -> Receiver chain
     */
    private void handleMixedICCFinal(Intent intent) {
        String targetPath = intent.getStringExtra("target_path");
        String chainStep = intent.getStringExtra("chain_step");

        if ("final".equals(chainStep) && targetPath != null) {
            try {
                FileOutputStream fos = new FileOutputStream(targetPath);
                fos.write("mixed ICC chain complete".getBytes());  // Target sink
                fos.close();
            } catch (IOException e) {
                // Handle exception
            }
        }
    }
}