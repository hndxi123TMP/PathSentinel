#!/bin/bash

# PathSentinel Ground Truth Validation Runner
# This script runs the complete validation pipeline

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATION_DIR="$SCRIPT_DIR/validation"

echo "=========================================="
echo "PathSentinel Ground Truth Validation"
echo "=========================================="
echo

# Check if Java is available
if ! command -v java &> /dev/null; then
    echo "ERROR: Java is not installed or not in PATH"
    exit 1
fi

# Check if Gradle wrapper is available
if [ ! -f "$SCRIPT_DIR/gradlew" ]; then
    echo "ERROR: Gradle wrapper not found in $SCRIPT_DIR"
    exit 1
fi

# Make sure gradlew is executable
chmod +x "$SCRIPT_DIR/gradlew"

echo "Starting validation pipeline..."
echo "Working directory: $SCRIPT_DIR"
echo

# Compile validation framework
echo "Compiling validation framework..."
cd "$VALIDATION_DIR"

# Simple compilation (assumes Java classpath is set up)
javac -cp ".:$HOME/.gradle/caches/modules-2/files-2.1/com.google.code.gson/gson/*/gson-*.jar" *.java

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to compile validation framework"
    echo "Make sure Gson library is in classpath"
    exit 1
fi

echo "✓ Validation framework compiled successfully"
echo

# Run automated validation
echo "Running automated validation..."
java -cp ".:$HOME/.gradle/caches/modules-2/files-2.1/com.google.code.gson/gson/*/gson-*.jar" AutomatedTestRunner

VALIDATION_EXIT_CODE=$?

echo
echo "=========================================="
if [ $VALIDATION_EXIT_CODE -eq 0 ]; then
    echo "✓ VALIDATION PASSED"
    echo "PathSentinel meets ground truth expectations"
elif [ $VALIDATION_EXIT_CODE -eq 1 ]; then
    echo "✗ VALIDATION FAILED"  
    echo "PathSentinel has significant issues"
elif [ $VALIDATION_EXIT_CODE -eq 2 ]; then
    echo "⚠ VALIDATION ERROR"
    echo "Framework encountered fatal error"
else
    echo "? VALIDATION UNKNOWN"
    echo "Unexpected exit code: $VALIDATION_EXIT_CODE"
fi
echo "=========================================="
echo

# Show report locations
if [ -d "$VALIDATION_DIR/reports" ]; then
    echo "Reports generated:"
    ls -la "$VALIDATION_DIR/reports/latest_validation_report"*
    echo
    echo "View HTML report: file://$VALIDATION_DIR/reports/latest_validation_report.html"
fi

exit $VALIDATION_EXIT_CODE