package com.test.pathsent_tester;

import android.app.Activity;
import android.os.Bundle;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * DirectFileTests - 10 execution paths for direct file operations testing.
 * Each method has exactly 1 path to a sink from targetedMethods.txt.
 */
public class DirectFileTests extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }

    // Hijacking tests (3 paths) - hardcoded paths

    /**
     * Path DIRECT_1: Direct file operation with hardcoded path
     * Entry point: DirectFileTests.hijackingTest1
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     * Path type: HIJACKING/HARD_CODED
     */
    public void hijackingTest1() {
        try {
            String path = "/data/hijack1.txt";  // HARD_CODED
            FileOutputStream fos = new FileOutputStream(path);
            fos.write("hijack test 1".getBytes());
            fos.close();
        } catch (IOException e) {
            // Handle exception
        }
    }

    /**
     * Path DIRECT_2: Direct file operation with hardcoded path
     * Entry point: DirectFileTests.hijackingTest2
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     * Path type: HIJACKING/HARD_CODED
     */
    public void hijackingTest2() {
        try {
            String path = "/data/hijack2.txt";  // HARD_CODED
            FileOutputStream fos = new FileOutputStream(path);
            fos.write("hijack test 2".getBytes());
            fos.close();
        } catch (IOException e) {
            // Handle exception
        }
    }

    /**
     * Path DIRECT_3: Direct file operation with hardcoded path
     * Entry point: DirectFileTests.hijackingTest3
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     * Path type: HIJACKING/HARD_CODED
     */
    public void hijackingTest3() {
        try {
            String path = "/data/hijack3.txt";  // HARD_CODED
            FileOutputStream fos = new FileOutputStream(path);
            fos.write("hijack test 3".getBytes());
            fos.close();
        } catch (IOException e) {
            // Handle exception
        }
    }

    // Traversal tests (3 paths) - user input to path

    /**
     * Path DIRECT_4: Path traversal with user input
     * Entry point: DirectFileTests.traversalTest1
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     * Path type: TRAVERSAL/USER_INPUT
     */
    public void traversalTest1(String userInput) {
        try {
            if (userInput != null && userInput.length() > 0) {
                String path = "/data/user/" + userInput + ".txt";  // USER_INPUT
                FileOutputStream fos = new FileOutputStream(path);
                fos.write("traversal test 1".getBytes());
                fos.close();
            }
        } catch (IOException e) {
            // Handle exception
        }
    }

    /**
     * Path DIRECT_5: Path traversal with user input and validation
     * Entry point: DirectFileTests.traversalTest2
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     * Path type: TRAVERSAL/USER_INPUT
     */
    public void traversalTest2(String userInput) {
        try {
            if (userInput != null && userInput.length() > 5) {
                String path = "/data/validated/" + userInput + ".log";  // USER_INPUT
                FileOutputStream fos = new FileOutputStream(path);
                fos.write("traversal test 2".getBytes());
                fos.close();
            }
        } catch (IOException e) {
            // Handle exception
        }
    }

    /**
     * Path DIRECT_6: Path traversal with multiple user inputs
     * Entry point: DirectFileTests.traversalTest3
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     * Path type: TRAVERSAL/USER_INPUT
     */
    public void traversalTest3(String prefix, String suffix) {
        try {
            if (prefix != null && suffix != null) {
                String path = "/data/" + prefix + "_combined_" + suffix + ".dat";  // USER_INPUT
                FileOutputStream fos = new FileOutputStream(path);
                fos.write("traversal test 3".getBytes());
                fos.close();
            }
        } catch (IOException e) {
            // Handle exception
        }
    }

    // Execution-only tests (4 paths) - no string parameters

    /**
     * Path DIRECT_7: Execution-only with write(int)
     * Entry point: DirectFileTests.executionOnly1
     * Target sink: <java.io.FileOutputStream: void write(int)>
     * Path type: EXECUTION_ONLY
     */
    public void executionOnly1() {
        try {
            if (System.currentTimeMillis() > 0) {
                FileOutputStream fos = new FileOutputStream("/data/exec1.bin");
                fos.write(42);  // write(int) - no string param
                fos.close();
            }
        } catch (IOException e) {
            // Handle exception
        }
    }

    /**
     * Path DIRECT_8: Execution-only with write(byte[])
     * Entry point: DirectFileTests.executionOnly2
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     * Path type: EXECUTION_ONLY
     */
    public void executionOnly2() {
        try {
            boolean condition = true;
            if (condition) {
                FileOutputStream fos = new FileOutputStream("/data/exec2.bin");
                byte[] data = {1, 2, 3, 4, 5};
                fos.write(data);  // write(byte[]) - no string param
                fos.close();
            }
        } catch (IOException e) {
            // Handle exception
        }
    }

    /**
     * Path DIRECT_9: Execution-only with write(int) and condition
     * Entry point: DirectFileTests.executionOnly3
     * Target sink: <java.io.FileOutputStream: void write(int)>
     * Path type: EXECUTION_ONLY
     */
    public void executionOnly3() {
        try {
            int value = 10;
            if (value > 5) {
                FileOutputStream fos = new FileOutputStream("/data/exec3.bin");
                fos.write(value);  // write(int) - no string param
                fos.close();
            }
        } catch (IOException e) {
            // Handle exception
        }
    }

    /**
     * Path DIRECT_10: Execution-only with write(byte[]) and string condition
     * Entry point: DirectFileTests.executionOnly4
     * Target sink: <java.io.FileOutputStream: void write(byte[])>
     * Path type: EXECUTION_ONLY
     */
    public void executionOnly4() {
        try {
            String trigger = "execute";
            if ("execute".equals(trigger)) {
                FileOutputStream fos = new FileOutputStream("/data/exec4.bin");
                byte[] payload = "payload".getBytes();
                fos.write(payload);  // write(byte[]) - no string param
                fos.close();
            }
        } catch (IOException e) {
            // Handle exception
        }
    }
}