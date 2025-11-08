#!/bin/bash
# format-logs.sh - Simple log formatter without jq dependency

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

while IFS= read -r line; do
    # Check if line looks like JSON
    if [[ "$line" =~ ^\{.*\}$ ]]; then
        # Extract level
        if [[ "$line" =~ \"level\":\"([^\"]+)\" ]]; then
            level="${BASH_REMATCH[1]}"
        else
            level="INFO"
        fi
        
        # Extract message
        if [[ "$line" =~ \"message\":\"([^\"]+)\" ]]; then
            message="${BASH_REMATCH[1]}"
        else
            message=""
        fi
        
        # Extract component
        if [[ "$line" =~ \"component\":\"([^\"]+)\" ]]; then
            component="${BASH_REMATCH[1]}"
        else
            component=""
        fi
        
        # Extract test name
        if [[ "$line" =~ \"testName\":\"([^\"]+)\" ]]; then
            testName="${BASH_REMATCH[1]}"
        else
            testName=""
        fi
        
        # Extract result
        if [[ "$line" =~ \"result\":\"([^\"]+)\" ]]; then
            result="${BASH_REMATCH[1]}"
        else
            result=""
        fi
        
        # Get timestamp
        timestamp=$(date '+%H:%M:%S')
        
        # Color and symbol based on level
        case "${level^^}" in
            ERROR)
                color=$RED
                symbol="✗"
                ;;
            WARN*)
                color=$YELLOW
                symbol="⚠"
                ;;
            INFO)
                color=$GREEN
                symbol="ℹ"
                ;;
            DEBUG)
                # Skip debug messages when LOG_LEVEL is info
                continue
                ;;
            *)
                color=$NC
                symbol="·"
                ;;
        esac
        
        # Build output
        output="${GRAY}${timestamp}${NC} ${color}${symbol}${NC}"
        
        # Add component
        if [ -n "$component" ]; then
            output="${output} ${CYAN}[${component}]${NC}"
        fi
        
        # Add message
        if [ -n "$message" ]; then
            output="${output} ${message}"
        fi
        
        # Add test info
        if [ -n "$testName" ]; then
            output="${output} ${BLUE}${testName}${NC}"
            
            if [ "$result" = "passed" ]; then
                output="${output} ${GREEN}✓${NC}"
            elif [[ "$result" =~ "not-passed" ]]; then
                output="${output} ${RED}✗${NC}"
            fi
        fi
        
        echo -e "$output"
    else
        # Not JSON, print as-is with timestamp
        timestamp=$(date '+%H:%M:%S')
        echo -e "${GRAY}${timestamp}${NC} $line"
    fi
done
