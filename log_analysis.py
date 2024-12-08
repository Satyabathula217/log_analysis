import csv
from collections import defaultdict

# Constants
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    return lines

def count_requests_per_ip(log_lines):
    ip_count = defaultdict(int)
    
    for line in log_lines:
        parts = line.split()
        ip_address = parts[0]
        ip_count[ip_address] += 1
    
    return dict(ip_count)

def identify_most_accessed_endpoint(log_lines):
    endpoint_count = defaultdict(int)
    
    for line in log_lines:
        parts = line.split('"')
        if len(parts) > 1:
            request = parts[1].split()
            if len(request) > 1:
                endpoint = request[1]
                endpoint_count[endpoint] += 1
    
    most_accessed = max(endpoint_count.items(), key=lambda x: x[1], default=(None, 0))
    return most_accessed

def detect_suspicious_activity(log_lines):
    failed_logins = defaultdict(int)
    
    for line in log_lines:
        if '401' in line or 'Invalid credentials' in line:
            parts = line.split()
            ip_address = parts[0]
            failed_logins[ip_address] += 1
    
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    return suspicious_ips

def save_results_to_csv(ip_counts, most_accessed, suspicious_ips):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        fieldnames = ['IP Address', 'Request Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for ip, count in ip_counts.items():
            writer.writerow({'IP Address': ip, 'Request Count': count})
        
        # Add most accessed endpoint to the CSV
        writer.writerow({'IP Address': 'Most Accessed Endpoint', 'Request Count': most_accessed[0]})
        
        # Add suspicious IPs to the CSV
        for ip, count in suspicious_ips.items():
            writer.writerow({'IP Address': f'Suspicious IP: {ip}', 'Request Count': count})

if __name__ == "__main__":
    log_lines = parse_log_file('sample.log')
    ip_counts = count_requests_per_ip(log_lines)
    most_accessed = identify_most_accessed_endpoint(log_lines)
    suspicious_ips = detect_suspicious_activity(log_lines)
    save_results_to_csv(ip_counts, most_accessed, suspicious_ips)