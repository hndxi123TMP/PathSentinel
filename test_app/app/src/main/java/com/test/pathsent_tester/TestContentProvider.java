package com.test.pathsent_tester;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * TestContentProvider - Handles ContentProvider ICC patterns.
 */
public class TestContentProvider extends ContentProvider {

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        if (uri != null && values != null) {
            String path = uri.getPath();

            // Basic ContentProvider ICC patterns (paths ICC_5 and ICC_6)
            if (path.contains("/files/test1")) {
                handleProviderTest1(values);
            } else if (path.contains("/files/test2")) {
                handleProviderTest2(values);
            }
            // Multi-hop ICC pattern (path COMPLEX_2 continuation)
            else if (path.contains("/multihop/step2")) {
                handleMultiHopStep2(values);
            }
            // Mixed ICC pattern (path COMPLEX_5 middle step)
            else if (path.contains("/mixed/chain")) {
                handleMixedICCChain(values);
            }
        }
        return uri;
    }

    /**
     * Handles PROVIDER ICC path ICC_5
     * Constraint: uri contains "/files/test1"
     */
    private void handleProviderTest1(ContentValues values) {
        String fileName = values.getAsString("file_name");
        String filePath = values.getAsString("file_path");
        String content = values.getAsString("content");

        if ("provider1.dat".equals(fileName) && filePath != null && content != null) {
            try {
                FileOutputStream fos = new FileOutputStream(filePath);
                fos.write(content.getBytes());  // Target sink
                fos.close();
            } catch (IOException e) {
                // Handle exception
            }
        }
    }

    /**
     * Handles PROVIDER ICC path ICC_6
     * Constraint: uri contains "/files/test2"
     */
    private void handleProviderTest2(ContentValues values) {
        String fileName = values.getAsString("file_name");
        String filePath = values.getAsString("file_path");
        String content = values.getAsString("content");

        if ("provider2.dat".equals(fileName) && filePath != null && content != null) {
            try {
                FileOutputStream fos = new FileOutputStream(filePath);
                fos.write(content.getBytes());  // Target sink
                fos.close();
            } catch (IOException e) {
                // Handle exception
            }
        }
    }

    /**
     * Handles multi-hop ICC path COMPLEX_2 (final step)
     * Service -> Provider continuation
     */
    private void handleMultiHopStep2(ContentValues values) {
        String source = values.getAsString("source");
        String multihopPath = values.getAsString("multihop_path");
        String content = values.getAsString("content");

        if ("service".equals(source) && multihopPath != null && content != null) {
            try {
                FileOutputStream fos = new FileOutputStream(multihopPath);
                fos.write(("multihop service->provider: " + content).getBytes());  // Target sink
                fos.close();
            } catch (IOException e) {
                // Handle exception
            }
        }
    }

    /**
     * Handles mixed ICC path COMPLEX_5 (middle step)
     * Part 2 of Service -> Provider -> Receiver chain
     */
    private void handleMixedICCChain(ContentValues values) {
        String chainStep = values.getAsString("chain_step");
        String targetPath = values.getAsString("target_path");
        String content = values.getAsString("content");

        if ("provider".equals(chainStep) && targetPath != null && content != null) {
            // Continue to final broadcast step
            Intent finalIntent = new Intent("ACTION_MIXED_FINAL");
            finalIntent.putExtra("chain_step", "final");
            finalIntent.putExtra("target_path", targetPath);
            finalIntent.putExtra("content", content);
            getContext().sendBroadcast(finalIntent);
        }
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}