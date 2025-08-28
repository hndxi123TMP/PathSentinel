package com.test.pathsent_tester;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

/**
 * MainActivity - Minimal launcher for the ICC-focused test suite.
 * This application contains exactly 25 execution paths for PathSentinel testing:
 * - 10 paths in BasicICCTests (various ICC patterns)
 * - 10 paths in DirectFileTests (direct file operations)
 * - 5 paths in ComplexICCTests (multi-hop and complex ICC)
 */
public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // This is a minimal launcher activity
        // The actual test entry points are in:
        // - BasicICCTests.java (10 paths)
        // - DirectFileTests.java (10 paths) 
        // - ComplexICCTests.java (5 paths)
        //
        // Total: 25 execution paths
        //
        // See ground_truth.json for complete path documentation
    }
    
    /**
     * Trigger basic ICC tests programmatically
     */
    public void triggerBasicICCTests() {
        Intent intent = new Intent(this, BasicICCTests.class);
        startActivity(intent);
    }
    
    /**
     * Trigger direct file tests programmatically  
     */
    public void triggerDirectFileTests() {
        Intent intent = new Intent(this, DirectFileTests.class);
        startActivity(intent);
    }
    
    /**
     * Trigger complex ICC tests programmatically
     */
    public void triggerComplexICCTests() {
        Intent intent = new Intent(this, ComplexICCTests.class);
        startActivity(intent);
    }
}