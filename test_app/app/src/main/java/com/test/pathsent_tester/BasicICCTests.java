package com.test.pathsent_tester;

import android.app.Activity;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;
import android.os.Messenger;

/**
 * BasicICCTests - 10 execution paths for Inter-Component Communication testing.
 * Each method has exactly 1 path to a sink from targetedMethods.txt.
 */
public class BasicICCTests extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }

    // ICC Pattern 1: startService (2 paths)
    
    /**
     * Path ICC_1: startService -> TestService.onStartCommand -> FileOutputStream.write(byte[])
     * Entry point: BasicICCTests.testStartService1
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     */
    public void testStartService1() {
        Intent intent = new Intent(this, TestService.class);
        intent.setAction("ACTION_TEST_1");
        intent.putExtra("file_path", "/data/icc_service1.txt");
        intent.putExtra("auth_level", "user");
        startService(intent);
    }

    /**
     * Path ICC_2: startService -> TestService.onStartCommand -> FileOutputStream.write(byte[])
     * Entry point: BasicICCTests.testStartService2
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     */
    public void testStartService2() {
        Intent intent = new Intent(this, TestService.class);
        intent.setAction("ACTION_TEST_2");
        intent.putExtra("file_path", "/data/icc_service2.txt");
        intent.putExtra("auth_level", "admin");
        startService(intent);
    }

    // ICC Pattern 2: sendBroadcast (2 paths)

    /**
     * Path ICC_3: sendBroadcast -> TestBroadcastReceiver.onReceive -> FileOutputStream.write(byte[])
     * Entry point: BasicICCTests.testSendBroadcast1
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     */
    public void testSendBroadcast1() {
        Intent intent = new Intent("ACTION_BROADCAST_1");
        intent.putExtra("log_data", "broadcast test 1");
        intent.putExtra("log_path", "/data/icc_broadcast1.log");
        sendBroadcast(intent);
    }

    /**
     * Path ICC_4: sendBroadcast -> TestBroadcastReceiver.onReceive -> FileOutputStream.write(byte[])
     * Entry point: BasicICCTests.testSendBroadcast2
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     */
    public void testSendBroadcast2() {
        Intent intent = new Intent("ACTION_BROADCAST_2");
        intent.putExtra("log_data", "broadcast test 2");
        intent.putExtra("log_path", "/data/icc_broadcast2.log");
        sendBroadcast(intent);
    }

    // ICC Pattern 3: ContentProvider (2 paths)

    /**
     * Path ICC_5: getContentResolver().insert -> TestContentProvider.insert -> FileOutputStream.write(byte[])
     * Entry point: BasicICCTests.testContentProvider1
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     */
    public void testContentProvider1() {
        Uri uri = Uri.parse("content://com.test.icc.provider/files/test1");
        ContentValues values = new ContentValues();
        values.put("file_name", "provider1.dat");
        values.put("file_path", "/data/icc_provider1.dat");
        values.put("content", "provider test 1");
        getContentResolver().insert(uri, values);
    }

    /**
     * Path ICC_6: getContentResolver().insert -> TestContentProvider.insert -> FileOutputStream.write(byte[])
     * Entry point: BasicICCTests.testContentProvider2
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     */
    public void testContentProvider2() {
        Uri uri = Uri.parse("content://com.test.icc.provider/files/test2");
        ContentValues values = new ContentValues();
        values.put("file_name", "provider2.dat");
        values.put("file_path", "/data/icc_provider2.dat");
        values.put("content", "provider test 2");
        getContentResolver().insert(uri, values);
    }

    // ICC Pattern 4: Dynamic registerReceiver (2 paths)

    /**
     * Path ICC_7: registerReceiver + sendBroadcast -> MyBroadcastReceiver.onReceive -> FileOutputStream.write(byte[])
     * Entry point: BasicICCTests.testRegisterReceiver1
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     */
    public void testRegisterReceiver1() {
        MyBroadcastReceiver receiver = new MyBroadcastReceiver("/data/dynamic1.log");
        IntentFilter filter = new IntentFilter("ACTION_DYNAMIC_1");
        registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED);

        Intent trigger = new Intent("ACTION_DYNAMIC_1");
        trigger.putExtra("test_data", "dynamic test 1");
        sendBroadcast(trigger);
    }

    /**
     * Path ICC_8: registerReceiver + sendBroadcast -> MyBroadcastReceiver.onReceive -> FileOutputStream.write(byte[])
     * Entry point: BasicICCTests.testRegisterReceiver2
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     */
    public void testRegisterReceiver2() {
        MyBroadcastReceiver receiver = new MyBroadcastReceiver("/data/dynamic2.log");
        IntentFilter filter = new IntentFilter("ACTION_DYNAMIC_2");
        registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED);

        Intent trigger = new Intent("ACTION_DYNAMIC_2");
        trigger.putExtra("test_data", "dynamic test 2");
        sendBroadcast(trigger);
    }

    // ICC Pattern 5: Messenger/Handler (2 paths)

    /**
     * Path ICC_9: Messenger.send -> TestHandler.handleMessage -> FileOutputStream.write(byte[])
     * Entry point: BasicICCTests.testMessenger1
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     */
    public void testMessenger1() {
        HandlerThread thread = new HandlerThread("test1");
        thread.start();
        TestHandler handler = new TestHandler(thread.getLooper(), "/data/messenger1.log");
        Messenger messenger = new Messenger(handler);

        try {
            Message msg = Message.obtain();
            msg.what = 1;
            msg.obj = "messenger test 1";
            messenger.send(msg);
        } catch (Exception e) {
            // Handle exception
        }
    }

    /**
     * Path ICC_10: Messenger.send -> TestHandler.handleMessage -> FileOutputStream.write(byte[])
     * Entry point: BasicICCTests.testMessenger2
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     */
    public void testMessenger2() {
        HandlerThread thread = new HandlerThread("test2");
        thread.start();
        TestHandler handler = new TestHandler(thread.getLooper(), "/data/messenger2.log");
        Messenger messenger = new Messenger(handler);

        try {
            Message msg = Message.obtain();
            msg.what = 2;
            msg.obj = "messenger test 2";
            messenger.send(msg);
        } catch (Exception e) {
            // Handle exception
        }
    }
}