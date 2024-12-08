import csv
from collections import defaultdict

# Function to count requests per IP address
def count_requests(log_file):
    ip_count = defaultdict(int)
    endpoint_count = defaultdict(int)
    failed_logins = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            parts = line.split()
            ip = parts[0]
            endpoint = parts[6]
            status_code = parts[8]

            # Count requests per IP
            ip_count[ip] += 1

            # Count endpoint accesses
            endpoint_count[endpoint] += 1

            # Detect failed login attempts
            if status_code == '401':
                failed_logins[ip] += 1

    return ip_count, endpoint_count, failed_logins

# Function to write results to CSV
def write_results(ip_count, endpoint_count, failed_logins, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_count.items():
            writer.writerow([ip, count])

        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        most_accessed = max(endpoint_count.items(), key=lambda x: x[1])
        writer.writerow(most_accessed)

        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Attempts'])
        for ip, count in failed_logins.items():
            if count > 10:  # Threshold for suspicious activity
                writer.writerow([ip, count])

# Main function
def main():
    log_file = 'sample.log'
    output_file = 'log_analysis_results.csv'
    
    ip_count, endpoint_count, failed_logins = count_requests(log_file)
    write_results(ip_count, endpoint_count, failed_logins, output_file)

if __name__ == "__main__":
    main()