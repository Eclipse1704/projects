#!/usr/bin/bash

  # Memory Forensics Function
memory_forensics() {
    echo "Running Memory Forensics..."
    
    # Set memory threshold in MB
    
    total_mem=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    total_mem_mb=$((total_mem / 1024))
    THRESHOLD=$((total_mem_mb / 10))
   
    echo "Hostname: $(hostname)" > high_memory_processes.txt
    echo "Timestamp: $(date)" >> high_memory_processes.txt
    echo "---------------------------------" >> high_memory_processes.txt

    # Collect and analyze memory usage
    ps aux --sort=-%mem | awk -v threshold=$THRESHOLD -v total=$total_mem_mb '
    NR>1 {
         mem_mb=$6/1024;
         if (mem_mb > threshold)
            printf "%-10s %-10s %-10s %-10.2f %-10s\n", $1, $2, $3, mem_mb, $11
         }
    ' >> high_memory_processes.txt

    if [[ $(wc -l high_memory_processes.txt) > 4 ]]; then 
    echo "High memory usage detected. See high_memory_processes.txt for details." 
    fi

    echo "Memory forensics completed. Results saved to high_memory_processes.txt."
}

  # Log Analysis Function
log_analysis() {
    echo "Running Advanced Log File Analysis..."

    
    LOG_FILES=("/var/log/auth.log" "/var/log/syslog" "/var/log/dmesg")  
    ANALYSIS_FILE="advanced_log_analysis.txt"
    PATTERNS=("Failed password" "error" "segfault" "unauthorized access")  
    DATE_RANGE="last 7 days"
    
    
    echo "Advanced Log Analysis Report" > $ANALYSIS_FILE
    echo "Date: $(date)" >> $ANALYSIS_FILE
    echo "---------------------------------" >> $ANALYSIS_FILE

    # Analyze each log file
    for LOG_FILE in "${LOG_FILES[@]}"; do
        echo "Analyzing $LOG_FILE..." >> $ANALYSIS_FILE

        # Extract logs from the specified date range
        echo "Extracting logs from $DATE_RANGE..." >> $ANALYSIS_FILE
        grep -iE "$(date --date='7 days ago' '+%b %e')" $LOG_FILE >> $ANALYSIS_FILE
        echo "---------------------------------" >> $ANALYSIS_FILE

        
        for PATTERN in "${PATTERNS[@]}"; do
            echo "Searching for pattern: $PATTERN" >> $ANALYSIS_FILE
            MATCHES=$(grep -ic "$PATTERN" $LOG_FILE)
            if [ $MATCHES -gt 0 ]; then
                echo "Found $MATCHES occurrences of '$PATTERN'" >> $ANALYSIS_FILE
                grep -i "$PATTERN" $LOG_FILE >> $ANALYSIS_FILE
                echo "---------------------------------" >> $ANALYSIS_FILE

                
                if [[ "$PATTERN" == *"unauthorized access"* || "$PATTERN" == *"segfault"* ]]; then
                    echo "Critical pattern detected: $PATTERN. Sending alert..." >> $ANALYSIS_FILE
                    echo "Critical alert: $PATTERN detected in $LOG_FILE" | mail -s "Log Analysis Alert" $EMAIL_ALERT
                fi
            else
                echo "No occurrences of '$PATTERN' found." >> $ANALYSIS_FILE
            fi
        done
    done

    # Summarize findings
    echo "Summary of Suspicious Activity:" >> $ANALYSIS_FILE
    for PATTERN in "${PATTERNS[@]}"; do
        echo "Pattern: $PATTERN" >> $ANALYSIS_FILE
        grep -i "$PATTERN" ${LOG_FILES[@]} | awk '{print $1, $2, $3, $11}' | sort | uniq -c | sort -nr >> $ANALYSIS_FILE
    done

    echo "Advanced log file analysis completed. Analysis saved to $ANALYSIS_FILE."
}
