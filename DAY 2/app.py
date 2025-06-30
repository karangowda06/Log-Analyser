import json
import streamlit as st
import re

class LogEntry:
    """
    A class to represent a single log entry with necessary fields.
    """
    def __init__(self, timestamp, event_type, action_type, user, target):
        self.timestamp = timestamp
        self.event_type = event_type
        self.action_type = action_type
        self.user = user
        self.target = target

    def to_dict(self):
        """
        Convert the LogEntry to a dictionary for easier handling.
        """
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "action_type": self.action_type,
            "user": self.user,
            "target": self.target
        }

    def __repr__(self):
        """
        Provide a readable representation for the LogEntry.
        """
        return f"LogEntry({self.timestamp}, {self.event_type}, {self.action_type}, {self.user}, {self.target})"


def parse_log_line(line):
    """
    Parse a single log line and return a LogEntry object.
    Gracefully handles malformed or corrupted lines by returning None.
    """
    try:
        # Regex to extract timestamp, event type, action, user, and target
        match = re.match(r"0x[0-9A-F]+\[ts:(\d+)\]\|EVNT:(\S+)!@(\S+):(\S+)=>(.+)", line)
        if match:
            timestamp = match.group(1)
            event_type = match.group(2)
            action_type = match.group(3)
            user = match.group(4)
            target = match.group(5)
            
            # Return a LogEntry object
            return LogEntry(timestamp, event_type, action_type, user, target)
        else:
            return None
    except Exception as e:
        print(f"Error parsing line: {line}. Exception: {e}")
        return None


def parse_log_file(file):
    """
    Parse a log file line-by-line and return a list of LogEntry objects.
    """
    log_entries = []
    
    # Decode the file content
    content = file.getvalue().decode("utf-8")  # Decode bytes to string
    
    # Split by lines
    lines = content.splitlines()
    
    # Parse each line
    for line in lines:
        log_entry = parse_log_line(line)
        if log_entry:
            log_entries.append(log_entry.to_dict())
    
    return log_entries


def main():
    st.title("Log File Parser")
    
    # Streamlit file uploader for selecting the log file
    log_file = st.file_uploader("Upload your log file", type=["vlog"])
    
    if log_file is not None:
        # Parse the uploaded log file
        parsed_logs = parse_log_file(log_file)

        # Check if logs were parsed
        if parsed_logs:
            # Display parsed logs in JSON format
            st.subheader("Parsed Log Entries:")
            st.json(parsed_logs)
        else:
            st.warning("No valid logs were found in the uploaded file.")
    else:
        st.info("Please upload a log file to parse.")

if __name__ == "__main__":
    main()
