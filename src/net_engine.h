#pragma once

#include <string>
#include <vector>
#include <map>
#include <windows.h>
#include <atomic>
#include <mutex>

// Structure to hold connection information
struct ConnectionInfo {
    std::string process_name;
    DWORD pid;
    std::string protocol;
    std::string local_addr;
    std::string remote_addr;
    std::string state;
    std::string adapter_name; // Adapter used by this connection
    
    // REAL network statistics from WinDivert
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t packets_sent = 0;
    uint64_t packets_received = 0;
    
    // Connection key for tracking
    std::string connection_key() const {
        return local_addr + "->" + remote_addr + ":" + std::to_string(pid);
    }
};

// Traffic monitor class using WFP (Windows Filtering Platform)
class TrafficMonitor {
public:
    static TrafficMonitor& Instance();
    
    void Start();
    void Stop();
    
    // Update traffic stats for a connection
    void AddSentBytes(const std::string& key, uint64_t bytes);
    void AddReceivedBytes(const std::string& key, uint64_t bytes);
    
    // Get current stats
    uint64_t GetSentBytes(const std::string& key);
    uint64_t GetReceivedBytes(const std::string& key);
    uint64_t GetSentPackets(const std::string& key);
    uint64_t GetReceivedPackets(const std::string& key);
    
    // Cleanup old connections that are no longer active
    void CleanupOldConnections(const std::vector<std::string>& active_keys);
    
    struct PacketInfo {
        std::string timestamp;
        bool outbound;
        uint32_t size;
        std::string flags;
        std::string payload_preview;
    };
    
    std::vector<PacketInfo> GetPacketHistory(const std::string& key);

private:
    TrafficMonitor() = default;
    ~TrafficMonitor() = default;
    
    std::mutex stats_mutex_;
    std::map<std::string, uint64_t> sent_bytes_;
    std::map<std::string, uint64_t> received_bytes_;
    std::map<std::string, uint64_t> sent_packets_;
    std::map<std::string, uint64_t> received_packets_;
    
    // Packet history: Key -> List of packets (max 1000 per key)
    std::map<std::string, std::vector<PacketInfo>> packet_history_;
    
    bool running_ = false;
};

// Network engine class
class NetEngine {
public:
    NetEngine();
    ~NetEngine();

    // Get all TCP connections
    std::vector<ConnectionInfo> GetTcpConnections();
    std::vector<ConnectionInfo> GetTcp6Connections();

    // Get all UDP connections  
    std::vector<ConnectionInfo> GetUdpConnections();
    std::vector<ConnectionInfo> GetUdp6Connections();

    // Get all connections (TCP + UDP, v4 + v6)
    std::vector<ConnectionInfo> GetAllConnections();
    
    struct AdapterStats {
        std::string alias;
        uint64_t recv_bytes = 0;
        uint64_t sent_bytes = 0;
        uint64_t recv_packets = 0;
        uint64_t sent_packets = 0;
        uint64_t ReceivedPacketErrors = 0;
        uint64_t OutboundPacketErrors = 0;
        uint64_t ReceivedDiscardedPackets = 0;
        uint64_t OutboundDiscardedPackets = 0;
    };
    
    // Get available network adapters
    std::vector<std::string> GetAdapters();

    // Get statistics for the main adapter (automatic) or a specific one
    AdapterStats GetEthernetStats(const std::string& specific_alias = "");

private:
    // Process name cache to avoid repeated lookups
    static std::map<DWORD, std::string> process_cache_;
    
    // Cache for mapping IP addresses to Adapter Names
    std::map<std::string, std::string> ip_to_adapter_cache_;
    void UpdateIpToAdapterCache();
    std::string GetAdapterNameFromIp(const std::string& ip_str);

    // Get process name from PID
    static std::string GetProcessName(DWORD pid);

    // Convert IP address to string
    static std::string IpToString(DWORD ip);
    static std::string Ipv6ToString(const BYTE* ipv6);

    // Convert TCP state to string
    static std::string TcpStateToString(DWORD state);
};
