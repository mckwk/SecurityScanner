import time
import psutil
import os
from ttkthemes import ThemedTk
from UI.gui import GUI

def measure_time(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"{func.__name__} execution time: {end_time - start_time:.2f} seconds")
        return result
    return wrapper

@measure_time
def initialize_gui():
    root = ThemedTk(theme="arc")
    app = GUI(root)
    return root, app

def start_main_loop(root):
    root.mainloop()

def measure_memory_usage():
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    return memory_info.rss  # in bytes

def measure_cpu_usage():
    process = psutil.Process(os.getpid())
    cpu_times = process.cpu_times()
    cpu_percent = process.cpu_percent(interval=1)
    return cpu_times, cpu_percent

def measure_disk_io():
    process = psutil.Process(os.getpid())
    io_counters = process.io_counters()
    return io_counters

def measure_network_usage():
    net_io = psutil.net_io_counters(pernic=False)
    return net_io

def measure_specific_aspects(app):
    # Measure time for network scan
    start_time = time.time()
    app.network_scanner.scan_network()
    end_time = time.time()
    print(f"Network scan execution time: {end_time - start_time:.2f} seconds")

    # Measure time for vulnerability search
    start_time = time.time()
    app.vulnerability_checker.search_vulnerabilities("test_model", "test_vendor")
    end_time = time.time()
    print(f"Vulnerability search execution time: {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    # Measure initialization time
    root, app = initialize_gui()

    # Measure specific aspects of the program
    measure_specific_aspects(app)

    # Measure memory usage
    mem_usage = measure_memory_usage()
    print(f"Memory Usage: {mem_usage / (1024 * 1024):.2f} MB")

    # Measure CPU usage
    cpu_times, cpu_percent = measure_cpu_usage()
    print(f"CPU User Time: {cpu_times.user:.2f} seconds")
    print(f"CPU System Time: {cpu_times.system:.2f} seconds")
    print(f"CPU Percent: {cpu_percent:.2f}%")

    # Measure disk I/O
    disk_io = measure_disk_io()
    print(f"Disk Read Count: {disk_io.read_count}")
    print(f"Disk Write Count: {disk_io.write_count}")
    print(f"Disk Read Bytes: {disk_io.read_bytes / (1024 * 1024):.2f} MB")
    print(f"Disk Write Bytes: {disk_io.write_bytes / (1024 * 1024):.2f} MB")

    # Measure network usage
    net_io = measure_network_usage()
    print(f"Bytes Sent: {net_io.bytes_sent / (1024 * 1024):.2f} MB")
    print(f"Bytes Received: {net_io.bytes_recv / (1024 * 1024):.2f} MB")

