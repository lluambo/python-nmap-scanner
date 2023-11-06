import nmap
from fpdf import FPDF
from datetime import datetime
import ipaddress

# Function to scan the specified network
def scan_network(network):
    nm = nmap.PortScanner()
    start_time = datetime.now()  # Record the start time of the scan
    nm.scan(hosts=network, arguments='-sn')
    end_time = datetime.now()    # Record the end time of the scan
    # Return a list of discovered hosts and scan times
    return nm.all_hosts(), start_time, end_time

# Function to calculate host range and broadcast IP address
def calculate_network_info(network):
    ip_net = ipaddress.ip_network(network, strict=False)
    host_range = f"Host Range: {ip_net.network_address + 1} - {ip_net.broadcast_address - 1}"
    broadcast_address = f"Broadcast IP: {ip_net.broadcast_address}"
    return host_range, broadcast_address

# Function to create a PDF report with network information
def create_pdf_report(hosts, start_time, end_time, host_range, broadcast_address):
    # Create a custom PDF class based on FPDF
    class PDF(FPDF):
        def header(self):
            self.set_font("Arial", "B", 12)
            self.cell(0, 10, "Network Scan Report", 0, 1, "C")

        def chapter_title(self, title):
            self.set_font("Arial", "B", 12)
            self.cell(0, 10, title, 0, 1, "L")
            self.ln(10)

        def chapter_body(self, body):
            self.set_font("Arial", "", 12)
            self.multi_cell(0, 10, body)
            self.ln()

    # Create a PDF instance
    pdf = PDF()
    pdf.add_page()
    pdf.chapter_title("Network Information:")
    # Add host range and broadcast IP address to the PDF report
    pdf.chapter_body(host_range)
    pdf.chapter_body(broadcast_address)
    pdf.chapter_title("List of Existing Hosts:")
    # Add each discovered host to the PDF report
    for host in hosts:
        pdf.chapter_body(host)
    # Add scan start and end times to the PDF report
    pdf.chapter_title("Scan Times:")
    pdf.chapter_body("Start Time: " + start_time.strftime("%Y-%m-%d %H:%M:%S"))
    pdf.chapter_body("End Time: " + end_time.strftime("%Y-%m-%d %H:%M:%S"))
    # Save the PDF report to a file
    pdf.output("network_scan_report.pdf")

if __name__ == "__main__":
    network = "192.168.1.0/24"  # Specify the target network to scan
    hosts, start_time, end_time = scan_network(network)
    host_range, broadcast_address = calculate_network_info(network)
    create_pdf_report(hosts, start_time, end_time, host_range, broadcast_address)
