package com.test.pathsent_tester;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * TestHandler - Handles Messenger/Handler ICC patterns.
 */
public class TestHandler extends Handler {

    private String logPath;

    public TestHandler(Looper looper, String logPath) {
        super(looper);
        this.logPath = logPath;
    }

    @Override
    public void handleMessage(Message msg) {
        if (msg != null && logPath != null) {
            // Messenger ICC patterns (paths ICC_9 and ICC_10)
            if (msg.what == 1 && "/data/messenger1.log".equals(logPath)) {
                handleMessengerTest1(msg);
            } else if (msg.what == 2 && "/data/messenger2.log".equals(logPath)) {
                handleMessengerTest2(msg);
            }
        }
    }

    /**
     * Handles MESSENGER ICC path ICC_9
     * Constraint: msg.what = 1 AND logPath = "/data/messenger1.log"
     */
    private void handleMessengerTest1(Message msg) {
        if (msg.obj instanceof String) {
            String testData = (String) msg.obj;
            if ("messenger test 1".equals(testData)) {
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

    /**
     * Handles MESSENGER ICC path ICC_10
     * Constraint: msg.what = 2 AND logPath = "/data/messenger2.log"
     */
    private void handleMessengerTest2(Message msg) {
        if (msg.obj instanceof String) {
            String testData = (String) msg.obj;
            if ("messenger test 2".equals(testData)) {
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
}