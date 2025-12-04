#!/bin/bash

###############################################################
#   Web Log Triage Tool - Level 3 Combined Detector
#   Safe for Incident Response. Detection only.
###############################################################

TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT="/tmp/triage-report-$TIMESTAMP.txt"

echo "======================================================" | tee -a $REPORT
echo "   Web Attack Triage Report - $TIMESTAMP" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT
echo "" | tee -a $REPORT


###############################
# 1. Ask user which server
###############################
echo "Select your web server:"
echo "  1) Apache"
echo "  2) Nginx"
read -p "Enter option (1 or 2): " SERVER

if [[ "$SERVER" == "1" ]]; then
    DEFAULT1="/var/log/apache2/access.log"
    DEFAULT2="/var/log/httpd/access_log"
    SERVER_NAME="Apache"
elif [[ "$SERVER" == "2" ]]; then
    DEFAULT1="/var/log/nginx/access.log"
    DEFAULT2="/var/log/nginx/access.log.1"
    SERVER_NAME="Nginx"
else
    echo "Invalid option. Exiting."
    exit 1
fi


###############################
# 2. Auto-detect log path
###############################
echo "" | tee -a $REPORT
echo "[*] Checking common $SERVER_NAME log locations..." | tee -a $REPORT

if [[ -f "$DEFAULT1" ]]; then
    LOG="$DEFAULT1"
elif [[ -f "$DEFAULT2" ]]; then
    LOG="$DEFAULT2"
else
    echo "[!] Could not automatically detect $SERVER_NAME log file."
    read -p "Please manually enter the full path of your access log: " LOG
fi

if [[ ! -f "$LOG" ]]; then
    echo "[ERROR] Log file not found: $LOG"
    echo "Exiting."
    exit 1
fi

echo "[+] Using log file: $LOG" | tee -a $REPORT
echo "" | tee -a $REPORT


###############################################################
# 3. Begin Triage Checks (Level 1 + Level 2 + Level 3)
###############################################################

echo "======================================================" | tee -a $REPORT
echo "  TOP ACTIVE IPs" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT

awk '{print $1}' $LOG | sort | uniq -c | sort -nr | head -20 | tee -a $REPORT


echo "" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT
echo "  SQL Injection Indicators" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT

grep -Ei "(%27|%22|--|union|select|insert|update|delete|drop|sleep|benchmark|concat|information_schema|extractvalue|updatexml|0x[0-9a-fA-F]+)" $LOG | tee -a $REPORT


echo "" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT
echo "  XSS Indicators" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT

grep -Ei "(<script|%3Cscript|javascript:|onerror=|onload=|alert\(|document\.cookie)" $LOG | tee -a $REPORT


echo "" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT
echo "  Command Injection Indicators" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT

grep -Ei "(;|&&|\|\||%26%26|%3B|wget|curl|nc |/bin/sh|/bin/bash|powershell|python|perl)" $LOG | tee -a $REPORT


echo "" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT
echo "  LFI/RFI Indicators" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT

grep -Ei "(php://|data://|input|expect://|file://|\.\./|\.\.%2f|etc/passwd|/proc/self)" $LOG | tee -a $REPORT


echo "" | tee -a $REPORT
echo "======================================================"" | tee -a $REPORT
echo "  Directory Traversal Indicators" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT

grep -Ei "(\.\.\/|\.\.%2f|%2e%2e%2f|%c0%af|%c1%9c)" $LOG | tee -a $REPORT


echo "" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT
echo "  Open Redirect Indicators" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT

grep -Ei "(redirect=|url=|next=|return=|dest=)" $LOG | grep -Ei "(http://|https://|%2f%2f|//)" | tee -a $REPORT


echo "" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT
echo "  Brute Force / Login Abuse (Auth Failures)" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT

grep -Ei "(login|signin|auth).*(failed|invalid|denied|incorrect)" $LOG | tee -a $REPORT


echo "" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT
echo "  Suspicious User Agents (Recon tools)" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT

grep -Ei "(sqlmap|nmap|nessus|nikto|acunetix|python-requests|curl|wget)" $LOG | tee -a $REPORT


echo "" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT
echo "  404 Abnormal Activity (Forced Browsing)" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT

awk '$9==404 {print $1}' $LOG | sort | uniq -c | sort -nr | head -20 | tee -a $REPORT


echo "" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT
echo "  High Entropy / Long Encoded Payloads (Possible Webshell Uploads)" | tee -a $REPORT
echo "======================================================" | tee -a $REPORT

grep -Eo "[A-Za-z0-9+/=]{60,}" $LOG | sort -u | tee -a $REPORT


echo "" | tee -a $REPORT
echo ""
echo "======================================================" | tee -a $REPORT
echo "Triage complete. Report generated at:" | tee -a $REPORT
echo "  $REPORT" | tee -a $REPORT
echo "======================================================"
echo ""
