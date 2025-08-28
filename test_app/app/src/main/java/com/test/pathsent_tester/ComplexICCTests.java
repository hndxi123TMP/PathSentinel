package com.test.pathsent_tester;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

/**
 * ComplexICCTests - 5 execution paths for complex ICC patterns.
 * Each method has exactly 1 path to a sink from targetedMethods.txt.
 */
public class ComplexICCTests extends Activity {

    // Static field for ICC communication
    public static String SHARED_DATA = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }

    // Multi-hop ICC (2 paths)

    /**
     * Path COMPLEX_1: Multi-hop ICC through service then broadcast
     * Entry point: ComplexICCTests.multiHopICC1
     * ICC chain: ComplexICCTests -> TestService -> sendBroadcast -> TestBroadcastReceiver
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     * Path type: MULTI_HOP_ICC
     */
    public void multiHopICC1() {
        SHARED_DATA = "/data/multihop1.txt";

        Intent step1 = new Intent(this, TestService.class);
        step1.setAction("ACTION_MULTIHOP_1");
        step1.putExtra("next_step", "broadcast");
        startService(step1);
    }

    /**
     * Path COMPLEX_2: Multi-hop ICC through service then content provider
     * Entry point: ComplexICCTests.multiHopICC2
     * ICC chain: ComplexICCTests -> TestService -> ContentProvider -> TestContentProvider
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     * Path type: MULTI_HOP_ICC
     */
    public void multiHopICC2() {
        SHARED_DATA = "/data/multihop2.txt";

        Intent step1 = new Intent(this, TestService.class);
        step1.setAction("ACTION_MULTIHOP_2");
        step1.putExtra("next_step", "provider");
        startService(step1);
    }

    // Static field ICC (2 paths)

    /**
     * Path COMPLEX_3: Static field communication with broadcast
     * Entry point: ComplexICCTests.staticFieldICC1
     * ICC pattern: Static field + sendBroadcast -> TestBroadcastReceiver
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     * Path type: STATIC_FIELD_ICC
     */
    public void staticFieldICC1() {
        SHARED_DATA = "static1_" + System.currentTimeMillis();

        Intent trigger = new Intent("ACTION_READ_STATIC_1");
        sendBroadcast(trigger);
    }

    /**
     * Path COMPLEX_4: Static field communication with broadcast
     * Entry point: ComplexICCTests.staticFieldICC2
     * ICC pattern: Static field + sendBroadcast -> TestBroadcastReceiver
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     * Path type: STATIC_FIELD_ICC
     */
    public void staticFieldICC2() {
        SHARED_DATA = "static2_" + System.currentTimeMillis();

        Intent trigger = new Intent("ACTION_READ_STATIC_2");
        sendBroadcast(trigger);
    }

    // Mixed ICC types (1 path)

    /**
     * Path COMPLEX_5: Mixed ICC types in a chain
     * Entry point: ComplexICCTests.mixedICC
     * ICC chain: Service -> Provider -> Receiver chain
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     * Path type: MIXED_ICC
     */
    public void mixedICC() {
        // Service -> Provider -> Receiver chain
        Intent serviceIntent = new Intent(this, TestService.class);
        serviceIntent.setAction("ACTION_MIXED_START");
        serviceIntent.putExtra("target_path", "/data/mixed_icc.txt");
        startService(serviceIntent);
    }
}