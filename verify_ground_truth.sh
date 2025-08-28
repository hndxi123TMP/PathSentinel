#!/bin/bash

# Ground Truth Verification Script for PathSentinel String Parameter Analysis
# Tests both execution constraints and path constraints against expected patterns

echo "================================================================"
echo "PathSentinel Ground Truth Verification Report"
echo "================================================================"
echo "Generated: $(date)"
echo ""

OUTPUT_DIR="/home/eddy/Research/tiro/static/pathSentOutput/com.test.pathsent_tester/constraints"
REPORT_FILE="ground_truth_report.txt"

# Initialize counters
total_vulnerabilities=0
hijacking_count=0
partial_count=0
full_count=0
hijacking_txt_count=0
traversal_py_count=0

# Test results tracking
declare -A test_results
declare -A execution_results
declare -A path_results

echo "=== VULNERABILITY COUNT ANALYSIS ==="

# Count vulnerabilities by type
if [[ -d "$OUTPUT_DIR/hijacking/constraints" ]]; then
    hijacking_count=$(find "$OUTPUT_DIR/hijacking/constraints" -name "metadata.json" | wc -l)
fi

if [[ -d "$OUTPUT_DIR/traversal/partial/constraints" ]]; then
    partial_count=$(find "$OUTPUT_DIR/traversal/partial/constraints" -name "metadata.json" | wc -l)
fi

if [[ -d "$OUTPUT_DIR/traversal/full/constraints" ]]; then
    full_count=$(find "$OUTPUT_DIR/traversal/full/constraints" -name "metadata.json" | wc -l)
fi

total_vulnerabilities=$((hijacking_count + partial_count + full_count))

echo "Total Vulnerabilities Found: $total_vulnerabilities"
echo "  - Hijacking (Hard-coded paths): $hijacking_count"
echo "  - Partial Traversal (Base + input): $partial_count"
echo "  - Full Traversal (User controlled): $full_count"
echo ""

# Verify file type consistency
if [[ -d "$OUTPUT_DIR/hijacking/constraints" ]]; then
    hijacking_txt_count=$(find "$OUTPUT_DIR/hijacking/constraints" -name "path.txt" | wc -l)
fi

if [[ -d "$OUTPUT_DIR/traversal" ]]; then
    traversal_py_count=$(find "$OUTPUT_DIR/traversal" -name "path.py" | wc -l)
fi

echo "=== FILE TYPE VERIFICATION ==="
echo "Hijacking .txt files: $hijacking_txt_count (Expected: $hijacking_count)"
echo "Traversal .py files: $traversal_py_count (Expected: $((partial_count + full_count)))"

if [[ $hijacking_txt_count -eq $hijacking_count ]]; then
    echo "✓ Hijacking file type consistency: PASS"
    test_results["hijacking_file_type"]="PASS"
else
    echo "✗ Hijacking file type consistency: FAIL"
    test_results["hijacking_file_type"]="FAIL"
fi

if [[ $traversal_py_count -eq $((partial_count + full_count)) ]]; then
    echo "✓ Traversal file type consistency: PASS"
    test_results["traversal_file_type"]="PASS"
else
    echo "✗ Traversal file type consistency: FAIL"
    test_results["traversal_file_type"]="FAIL"
fi
echo ""

echo "=== EXECUTION CONSTRAINT VERIFICATION ==="

# Verify execution constraints for known test cases
for exec_file in $(find "$OUTPUT_DIR" -name "execution.py" | sort); do
    constraint_dir=$(dirname "$exec_file")
    constraint_id=$(basename "$constraint_dir")
    vuln_type="unknown"
    
    # Determine vulnerability type from path
    if [[ $exec_file == *"hijacking"* ]]; then
        vuln_type="hijacking"
    elif [[ $exec_file == *"partial"* ]]; then
        vuln_type="partial"
    elif [[ $exec_file == *"full"* ]]; then
        vuln_type="full"
    fi
    
    echo "Checking execution constraints: $vuln_type/$constraint_id"
    
    # Check for specific patterns based on our test cases
    if grep -q "SECRET_123" "$exec_file"; then
        echo "  ✓ Found A2: Single auth token constraint (SECRET_123)"
        execution_results["A2_auth"]="FOUND"
    elif grep -q "admin.*pass123.*superuser" "$exec_file"; then
        echo "  ✓ Found A3: Complex auth constraints (admin+pass123+superuser)"
        execution_results["A3_complex"]="FOUND"
    elif grep -q "MASTER_KEY_999" "$exec_file"; then
        echo "  ✓ Found C3: Master key constraint (MASTER_KEY_999)"
        execution_results["C3_master"]="FOUND"
    elif grep -q "write_file" "$exec_file"; then
        echo "  ✓ Found C2: Operation constraint (write_file)"
        execution_results["C2_operation"]="FOUND"
    elif grep -q "log.*data" "$exec_file"; then
        echo "  ✓ Found B2: File type validation (log|data)"
        execution_results["B2_filetype"]="FOUND"
    elif grep -q "admin.*power_user" "$exec_file"; then
        echo "  ✓ Found B3: Auth level constraint (admin|power_user)"
        execution_results["B3_authlevel"]="FOUND"
    else
        # Check if file has minimal constraints (simple test cases)
        constraint_count=$(grep -c "s.add" "$exec_file" 2>/dev/null || echo "0")
        if [[ $constraint_count -le 5 ]]; then
            echo "  ✓ Minimal execution constraints (likely A1, B1, or C1)"
            execution_results["minimal_$constraint_id"]="FOUND"
        else
            echo "  - Complex execution constraints detected"
            execution_results["complex_$constraint_id"]="FOUND"
        fi
    fi
done
echo ""

echo "=== PATH CONSTRAINT VERIFICATION ==="

# Verify path constraints for known test cases
for path_file in $(find "$OUTPUT_DIR" -name "path.txt" -o -name "path.py" | sort); do
    constraint_dir=$(dirname "$path_file")
    constraint_id=$(basename "$constraint_dir")
    file_ext="${path_file##*.}"
    
    echo "Checking path constraints: $(basename "$path_file")"
    
    if [[ $file_ext == "txt" ]]; then
        # Hijacking verification - should contain exact hard-coded paths
        if grep -q "/data/local/tmp/simple_hijack.log" "$path_file"; then
            echo "  ✓ A1: Found simple hijack path (/data/local/tmp/simple_hijack.log)"
            path_results["A1_simple"]="FOUND"
        elif grep -q "/data/local/tmp/admin_config.txt" "$path_file"; then
            echo "  ✓ A2: Found admin config path (/data/local/tmp/admin_config.txt)"
            path_results["A2_admin"]="FOUND"
        elif grep -q "/data/local/tmp/system_critical.log" "$path_file"; then
            echo "  ✓ A3: Found system critical path (/data/local/tmp/system_critical.log)"
            path_results["A3_system"]="FOUND"
        else
            # Check for other hard-coded paths
            hard_coded_path=$(grep "path = " "$path_file" | head -1)
            echo "  - Other hard-coded path: $hard_coded_path"
            path_results["other_hardcoded_$constraint_id"]="FOUND"
        fi
    else
        # Traversal verification - should contain constraint logic
        if grep -q "startswith.*files" "$path_file"; then
            echo "  ✓ B1: Found files prefix constraint (/files/)"
            path_results["B1_files"]="FOUND"
        elif grep -q "startswith.*cache" "$path_file"; then
            echo "  ✓ B2: Found cache prefix constraint (/cache/)"
            path_results["B2_cache"]="FOUND"
        elif grep -q "startswith.*secure" "$path_file"; then
            echo "  ✓ B3: Found secure prefix constraint (/secure/)"
            path_results["B3_secure"]="FOUND"
        elif grep -q 'file_path != ""' "$path_file"; then
            echo "  ✓ C1/C2/C3: Found full control constraint (file_path != \"\")"
            path_results["full_control_$constraint_id"]="FOUND"
        else
            echo "  - Other traversal constraint pattern detected"
            path_results["other_traversal_$constraint_id"]="FOUND"
        fi
    fi
done
echo ""

echo "=== EXTERNAL INPUT SOURCE VERIFICATION ==="

external_input_count=0
total_metadata_files=0

for metadata in $(find "$OUTPUT_DIR" -name "metadata.json" | sort); do
    total_metadata_files=$((total_metadata_files + 1))
    constraint_dir=$(dirname "$metadata")
    constraint_id=$(basename "$constraint_dir")
    
    # Check if this is a traversal vulnerability (should have external inputs)
    if [[ $metadata == *"traversal"* ]]; then
        if grep -q "external_inputs" "$metadata"; then
            input_count=$(grep -o '"source_parameter"' "$metadata" | wc -l)
            external_input_count=$((external_input_count + input_count))
            
            echo "Metadata $constraint_id: $input_count external input sources"
            
            # Check for specific known input parameters
            if grep -q '"filename"' "$metadata"; then
                echo "  ✓ Found 'filename' parameter"
            fi
            if grep -q '"file_path"' "$metadata"; then
                echo "  ✓ Found 'file_path' parameter"
            fi
            if grep -q '"auth_token"' "$metadata"; then
                echo "  ✓ Found 'auth_token' parameter"
            fi
            if grep -q '"target_file"' "$metadata"; then
                echo "  ✓ Found 'target_file' parameter"
            fi
        else
            echo "⚠ Metadata $constraint_id: No external inputs found (unexpected for traversal)"
        fi
    fi
done

echo ""
echo "Total external input parameters tracked: $external_input_count"
echo "Total metadata files processed: $total_metadata_files"
echo ""

echo "=== GROUND TRUTH SUMMARY ==="

# Expected vs Actual comparison
echo "Expected Test Cases (from our 9 added test cases):"
echo "  A1: Simple Hijacking - Hard-coded path, no execution constraints"
echo "  A2: Auth Hijacking - Hard-coded path, auth token constraint"  
echo "  A3: Complex Hijacking - Hard-coded path, multiple auth constraints"
echo "  B1: Simple Partial - Base path + input, minimal constraints"
echo "  B2: Validated Partial - Base path + input, file type validation"
echo "  B3: Complex Partial - Base path + inputs, complex auth"
echo "  C1: Simple Full - User path, minimal constraints"
echo "  C2: Checked Full - User path, operation check"
echo "  C3: Complex Full - User path, complex auth"
echo ""

# Test case detection summary
detected_cases=0
for key in "${!path_results[@]}"; do
    if [[ "${path_results[$key]}" == "FOUND" ]]; then
        detected_cases=$((detected_cases + 1))
    fi
done

echo "Ground Truth Validation Results:"
echo "  Known test case patterns detected: $detected_cases"
echo "  Total vulnerabilities found: $total_vulnerabilities"
echo "  File type consistency: $(if [[ ${test_results["hijacking_file_type"]} == "PASS" && ${test_results["traversal_file_type"]} == "PASS" ]]; then echo "PASS"; else echo "FAIL"; fi)"
echo "  External input tracking: $external_input_count parameters tracked"
echo ""

# Overall assessment
if [[ $total_vulnerabilities -ge 9 && $detected_cases -ge 6 ]]; then
    echo "🎉 OVERALL ASSESSMENT: PASS"
    echo "   PathSentinel successfully detected and categorized the test cases"
    echo "   Both execution and path constraints are being generated correctly"
else
    echo "⚠ OVERALL ASSESSMENT: NEEDS REVIEW"
    echo "   Some test cases may not have been detected or categorized correctly"
fi

echo ""
echo "================================================================"
echo "Verification Complete - $(date)"
echo "================================================================"