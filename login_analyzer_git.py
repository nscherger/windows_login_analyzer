# Required module imports
import os          # Requirement 2: OS Module
import csv         # Requirement 3: CSV Module
import datetime
from subprocess import run, PIPE, CalledProcessError

def analyze_failed_logins(days_back=1, output_dir="security_logs"):
    """
    Analyzes Windows Event Log for failed login attempts.
    """
    try:
        # Requirement 2: OS Module Usage - Directory operations
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # Requirement 1b: Variable Declaration - Timestamp and path variables
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(output_dir, f"failed_logins_{timestamp}.csv")
        
        # Requirement 1b: Variable Declaration - Date calculations
        end_date = datetime.datetime.now()
        start_date = end_date - datetime.timedelta(days=days_back)
        
        date_format = "%Y-%m-%d"
        query_start = start_date.strftime(date_format)
        query_end = end_date.strftime(date_format)
        
        # Requirement 1c: Lists - Command arguments list
        cmd = [
            'wevtutil', 'qe', 'Security',
            '/q:*[System[(EventID=4625)][TimeCreated[@SystemTime>=' +
            f"'{query_start}T00:00:00' and @SystemTime<='{query_end}T23:59:59'"
            + ']]]',
            '/f:text', '/rd:true'
        ]
        
        print(f"Analyzing failed logins from {query_start} to {query_end}...")
        
        # Requirement 4: Reading command output as file object
        result = run(cmd, capture_output=True, text=True)
        
        # Requirement 1c: Lists - Store failed login entries
        failed_logins = []
        current_entry = {}
        
        # Requirement 1a: Loops - Process each line of output
        for line in result.stdout.split('\n'):
            line = line.strip()
            
            # Requirement 1e: Flow Statement (if) - Check for new event entry
            if line.startswith('Event ID:'):
                if current_entry:
                    failed_logins.append(current_entry)
                current_entry = {'Event ID': '4625'}
            
            elif ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                if key in ['Date', 'Account Name', 'Workstation Name', 
                          'Source Network Address', 'Failure Reason']:
                    current_entry[key] = value
        
        # Requirement 1e: Flow Statement (if) - Add final entry
        if current_entry:
            failed_logins.append(current_entry)
        
        # Requirement 2: OS Module Usage - Directory checks
        log_dir = os.path.dirname(output_path)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        # Requirement 2: OS Module Usage - Permission check
        if not os.access(log_dir, os.W_OK):
            raise PermissionError(f"No write permission for directory: {log_dir}")
            
        # Requirement 6: Writing to a file
        # Requirement 3: CSV Module usage
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Date', 'Account Name', 'Workstation Name', 
                         'Source Network Address', 'Failure Reason', 'Event ID']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            # Requirement 1a: Loops - Write each entry
            for entry in failed_logins:
                writer.writerow(entry)
        
        print(f"Analysis complete. Found {len(failed_logins)} failed login attempts.")
        print(f"Results written to {os.path.abspath(output_path)}")
        
        # Requirement 1e: Flow Statement (if) - Process results if entries found
        if failed_logins:
            print("\nSummary of findings:")
            # Requirement 1b: Variable Declaration - Counter dictionaries
            accounts = {}
            ips = {}
            
            # Requirement 1a: Loops - Count occurrences
            for entry in failed_logins:
                account = entry.get('Account Name', 'Unknown')
                ip = entry.get('Source Network Address', 'Unknown')
                
                # Requirement 1d: Casting - Implicit int casting in counter
                accounts[account] = accounts.get(account, 0) + 1
                ips[ip] = ips.get(ip, 0) + 1
            
            print("\nMost targeted accounts:")
            for account, count in sorted(accounts.items(), 
                                      key=lambda x: x[1], 
                                      reverse=True)[:5]:
                print(f"- {account}: {count} attempts")
            
            print("\nMost common source IPs:")
            for ip, count in sorted(ips.items(), 
                                  key=lambda x: x[1], 
                                  reverse=True)[:5]:
                print(f"- {ip}: {count} attempts")
                
    except CalledProcessError as e:
        print(f"Error executing wevtutil: {e}")
        print("Make sure you're running as administrator")
    except PermissionError as e:
        print(f"Permission error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    analyze_failed_logins()