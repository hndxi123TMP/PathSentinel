package com.test.pathsent_tester;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * MyBroadcastReceiver - Used for dynamic receiver registration patterns.
 */
public class MyBroadcastReceiver extends BroadcastReceiver {

    private String logPath;

    public MyBroadcastReceiver(String logPath) {
        this.logPath = logPath;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent != null && logPath != null) {
            String action = intent.getAction();

            // Dynamic receiver ICC patterns (paths ICC_7 and ICC_8)
            if ("ACTION_DYNAMIC_1".equals(action)) {
                handleDynamicReceiver1(intent);
            } else if ("ACTION_DYNAMIC_2".equals(action)) {
                handleDynamicReceiver2(intent);
            }
        }
    }

    /**
     * Handles dynamic receiver ICC path ICC_7
     * Constraint: action = "ACTION_DYNAMIC_1"
     */
    private void handleDynamicReceiver1(Intent intent) {
        String testData = intent.getStringExtra("test_data");

        if (testData != null && "/data/dynamic1.log".equals(logPath)) {
            try {
                FileOutputStream fos = new FileOutputStream(logPath);
                fos.write(testData.getBytes());  // Target sink
                fos.close();
            } catch (IOException e) {
                // Handle exception
            }
        }
    }

    /**
     * Handles dynamic receiver ICC path ICC_8
     * Constraint: action = "ACTION_DYNAMIC_2"
     */
    private void handleDynamicReceiver2(Intent intent) {
        String testData = intent.getStringExtra("test_data");

        if (testData != null && "/data/dynamic2.log".equals(logPath)) {
            try {
                FileOutputStream fos = new FileOutputStream(logPath);
                fos.write(testData.getBytes());  // Target sink
                fos.close();
            } catch (IOException e) {
                // Handle exception
            }
        }
    }
}