import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import pandas as pd
import sys

sys.path.append("D:\\file_transfer\\src\\application\\network\\statistics\\net_statistic.py")
from net_statistic import NetStatistics

class NetCharts:
    def __init__(self):
        self.net_stats_collector = NetStatistics()
        sns.set_theme(style="whitegrid")

    def plot_network_stats_over_time(self, start_date_str, end_date_str):
        """
        Plots bytes sent/received and packets sent/received over a specified date range.
        Dates should be in 'YYYY-MM-DD HH:MM:SS' format.
        """
        stats_data = self.net_stats_collector.getNetworkStatsByDate(start_date_str, end_date_str)
        if not stats_data:
            print("No network statistics found for the given date range.")
            return
        plt.rcParams['font.family'] = 'monospace'
        df = pd.DataFrame(stats_data)
        print(df)
        df['date'] = pd.to_datetime(df['date'])
        df = df.sort_values(by='date')

        plt.figure(figsize=(14, 7))

        # Plot Bytes Sent and Received
        plt.subplot(2, 1, 1)
        sns.lineplot(x='date', y='bytes_sent', data=df, label='Bytes Sent')
        sns.lineplot(x='date', y='bytes_recv', data=df, label='Bytes Received')
        plt.title('Network Bytes Transfer Over Time')
        plt.xlabel('Date')
        plt.ylabel('Bytes')
        plt.legend()
        plt.grid(True)

        # Plot Packets Sent and Received
        plt.subplot(2, 1, 2)
        sns.lineplot(x='date', y='packets_sent', data=df, label='Packets Sent')
        sns.lineplot(x='date', y='packets_recv', data=df, label='Packets Received')
        plt.title('Network Packets Transfer Over Time')
        plt.xlabel('Date')
        plt.ylabel('Packets')
        plt.legend()
        plt.grid(True)

        plt.tight_layout()
        plt.show()

    def plot_dropped_packets(self, start_date_str, end_date_str):
        """
        Plots dropped packets (in and out) over a specified date range.
        Dates should be in 'YYYY-MM-DD HH:MM:SS' format.
        """
        stats_data = self.net_stats_collector.getNetworkStatsByDate(start_date_str, end_date_str)
        if not stats_data:
            print("No network statistics found for the given date range.")
            return

        df = pd.DataFrame(stats_data)
        df['date'] = pd.to_datetime(df['date'])
        df = df.sort_values(by='date')

        plt.figure(figsize=(12, 6))
        sns.lineplot(x='date', y='dropin', data=df, label='Dropped In Packets')
        sns.lineplot(x='date', y='dropout', data=df, label='Dropped Out Packets')
        plt.title('Dropped Network Packets Over Time')
        plt.xlabel('Date')
        plt.ylabel('Number of Packets')
        plt.legend()
        plt.grid(True)
        plt.tight_layout()
        plt.show()

    def plot_file_transfer_volume(self, start_date_str, end_date_str):
        """
        Plots the total volume of files transferred (sent and received) by date.
        Dates should be in 'YYYY-MM-DD HH:MM:SS' format.
        """
        file_data = self.net_stats_collector.getTransferedFilesByDate(start_date_str, end_date_str)
        if not file_data:
            print("No file transfer data found for the given date range.")
            return

        df = pd.DataFrame(file_data)
        print(df)
        df['transfer_date'] = pd.to_datetime(df['transfer_date']).dt.date # Convert to date only for grouping
        
        # Group by date and sum sizes
        daily_transfer_volume = df.groupby('transfer_date')['size'].sum().reset_index()
        daily_transfer_volume['size_mb'] = daily_transfer_volume['size'] / (1024 * 1024) # Convert to MB

        plt.figure(figsize=(12, 6))
        sns.barplot(x='transfer_date', y='size_mb', data=daily_transfer_volume, palette='viridis')
        plt.title('Daily File Transfer Volume (MB)')
        plt.xlabel('Date')
        plt.ylabel('Volume (MB)')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.show()

    def plot_file_transfer_by_protocol(self, start_date_str, end_date_str):
        """
        Plots the distribution of file transfers by protocol (TCP vs UDP).
        Dates should be in 'YYYY-MM-DD HH:MM:SS' format.
        """
        file_data = self.net_stats_collector.getTransferedFilesByDate(start_date_str, end_date_str)
        if not file_data:
            print("No file transfer data found for the given date range.")
            return

        df = pd.DataFrame(file_data)
        
        #Ensure 'protocol' column exists and is used for grouping
        # Note: The current getTransferedFilesByDate query does not return 'protocol'.
        # You would need to modify the query in NetStatistics to include 'protocol'.
        # For demonstration, let's assume 'protocol' is available in the fetched data.
        
        # Example if 'protocol' was available:
        protocol_counts = df['protocol'].value_counts().reset_index()
        protocol_counts.columns = ['Protocol', 'Count']
        plt.figure(figsize=(8, 8))
        plt.pie(protocol_counts['Count'], labels=protocol_counts['Protocol'], autopct='%1.1f%%', startangle=90, colors=sns.color_palette('pastel'))
        plt.title('File Transfers by Protocol')
        # plt.axis('equal') # Equal aspect ratio ensures that pie is drawn as a circle.
        plt.show()

        # Placeholder if protocol is not directly available from getTransferedFilesByDate
        print("To plot file transfers by protocol, ensure 'protocol' is retrieved by getTransferedFilesByDate.")
        print("Example: df.groupby('protocol')['size'].sum().plot(kind='pie')")


# Example Usage (can be called from gui.py or app.py)
if __name__ == "__main__":
    charts = NetCharts()
    
    # Example: Plot network stats for a specific day
    # Ensure you have data logged for these dates in your logs.db
    start_date = "2023-01-01 00:00:00"
    end_date = "2023-12-31 23:59:59"

    # To test, first ensure you have run LogRecorder.addStatsLog() periodically
    # and LogRecorder.addFileLog() when files are transferred.
    
    charts.plot_network_stats_over_time(start_date, end_date)
    charts.plot_dropped_packets(start_date, end_date)
    charts.plot_file_transfer_volume(start_date, end_date)
    charts.plot_file_transfer_by_protocol(start_date, end_date) # Requires 'protocol' in DB query
