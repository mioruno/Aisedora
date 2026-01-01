// Network Engine with REAL WinDivert packet capture

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <tlhelp32.h>

#include "windivert.h"  // WinDivert API

#include "net_engine.h"
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <set>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// Initialize static members
std::map<DWORD, std::string> NetEngine::process_cache_;

// TrafficMonitor implementation with WinDivert
TrafficMonitor& TrafficMonitor::Instance() {
    static TrafficMonitor instance;
    return instance;
}

void TrafficMonitor::Start() {
    if (running_) return;
    running_ = true;
    
    // Start WinDivert capture thread
    std::thread capture_thread([this]() {
        // Open WinDivert handle for all TCP traffic
        HANDLE handle = WinDivertOpen("tcp", WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF);
        
        if (handle == INVALID_HANDLE_VALUE) {
            running_ = false;
            return;
        }
        
        unsigned char packet[WINDIVERT_MTU_MAX];
        UINT packet_len;
        WINDIVERT_ADDRESS addr;
        
        while (running_) {
            // Capture packet
            if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr)) {
                continue;
            }
            
            // Parse packet
            PWINDIVERT_IPHDR pIpHdr = nullptr;
            PWINDIVERT_TCPHDR pTcpHdr = nullptr;
            PVOID pData = nullptr;
            UINT dataLen = 0;
            
            WinDivertHelperParsePacket(
                packet, packet_len,
                &pIpHdr, nullptr,
                nullptr,
                nullptr, nullptr,
                &pTcpHdr, nullptr,
                &pData, &dataLen,
                nullptr, nullptr
            );
            
            if (pIpHdr && pTcpHdr) {
                // Format IP addresses
                char src_str[32], dst_str[32];
                sprintf_s(src_str, "%u.%u.%u.%u:%u",
                    pIpHdr->SrcAddr & 0xFF,
                    (pIpHdr->SrcAddr >> 8) & 0xFF,
                    (pIpHdr->SrcAddr >> 16) & 0xFF,
                    (pIpHdr->SrcAddr >> 24) & 0xFF,
                    ntohs(pTcpHdr->SrcPort));
                    
                sprintf_s(dst_str, "%u.%u.%u.%u:%u",
                    pIpHdr->DstAddr & 0xFF,
                    (pIpHdr->DstAddr >> 8) & 0xFF,
                    (pIpHdr->DstAddr >> 16) & 0xFF,
                    (pIpHdr->DstAddr >> 24) & 0xFF,
                    ntohs(pTcpHdr->DstPort));
                
                // Extract flags
                std::string flags;
                if (pTcpHdr->Fin) flags += "FIN ";
                if (pTcpHdr->Syn) flags += "SYN ";
                if (pTcpHdr->Rst) flags += "RST ";
                if (pTcpHdr->Psh) flags += "PSH ";
                if (pTcpHdr->Ack) flags += "ACK ";
                if (pTcpHdr->Urg) flags += "URG ";
                
                // Current time
                auto now = std::chrono::system_clock::now();
                auto time_t = std::chrono::system_clock::to_time_t(now);
                struct tm tm;
                localtime_s(&tm, &time_t);
                char time_str[32];
                strftime(time_str, sizeof(time_str), "%H:%M:%S", &tm);
                
                PacketInfo info;
                info.timestamp = time_str;
                info.outbound = addr.Outbound;
                info.size = packet_len;
                info.flags = flags;
                
                // Payload preview (hex)
                if (pData && dataLen > 0) {
                    char hex[16];
                    unsigned char* bytes = (unsigned char*)pData;
                    // Max 4 bytes preview
                    int n = (dataLen > 4) ? 4 : dataLen;
                    std::string preview = "0x";
                    for(int i=0; i<n; i++) {
                        sprintf_s(hex, "%02X", bytes[i]);
                        preview += hex;
                    }
                    if (dataLen > 4) preview += "...";
                    info.payload_preview = preview;
                } else {
                    info.payload_preview = "-";
                }

                std::lock_guard<std::mutex> lock(stats_mutex_);
                
                if (addr.Outbound) {
                    std::string key = std::string(src_str) + "->" + dst_str;
                    sent_bytes_[key] += packet_len;
                    sent_packets_[key]++;
                    
                    packet_history_[key].push_back(info);
                    if (packet_history_[key].size() > 500) packet_history_[key].erase(packet_history_[key].begin());
                } else {
                    std::string key = std::string(dst_str) + "->" + src_str;
                    received_bytes_[key] += packet_len;
                    received_packets_[key]++;
                    
                    packet_history_[key].push_back(info);
                    if (packet_history_[key].size() > 500) packet_history_[key].erase(packet_history_[key].begin());
                }
            }
        }
        
        WinDivertClose(handle);
    });
    
    capture_thread.detach();
}

void TrafficMonitor::Stop() {
    running_ = false;
}

void TrafficMonitor::AddSentBytes(const std::string& key, uint64_t bytes) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    sent_bytes_[key] += bytes;
}

void TrafficMonitor::AddReceivedBytes(const std::string& key, uint64_t bytes) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    received_bytes_[key] += bytes;
}

uint64_t TrafficMonitor::GetSentBytes(const std::string& key) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    auto it = sent_bytes_.find(key);
    return (it != sent_bytes_.end()) ? it->second : 0;
}

uint64_t TrafficMonitor::GetReceivedBytes(const std::string& key) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    auto it = received_bytes_.find(key);
    return (it != received_bytes_.end()) ? it->second : 0;
}

uint64_t TrafficMonitor::GetSentPackets(const std::string& key) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    auto it = sent_packets_.find(key);
    return (it != sent_packets_.end()) ? it->second : 0;
}

uint64_t TrafficMonitor::GetReceivedPackets(const std::string& key) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    auto it = received_packets_.find(key);
    return (it != received_packets_.end()) ? it->second : 0;
}

void TrafficMonitor::CleanupOldConnections(const std::vector<std::string>& active_keys) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    // Create set of active keys for fast lookup
    std::set<std::string> active_set(active_keys.begin(), active_keys.end());
    
    // Remove keys that are not in active set
    auto cleanup_map = [&active_set](auto& map) {
        for (auto it = map.begin(); it != map.end(); ) {
            if (active_set.find(it->first) == active_set.end()) {
                it = map.erase(it);
            } else {
                ++it;
            }
        }
    };
    
    cleanup_map(sent_bytes_);
    cleanup_map(received_bytes_);
    cleanup_map(sent_packets_);
    cleanup_map(received_packets_);
    cleanup_map(packet_history_);
}

std::vector<TrafficMonitor::PacketInfo> TrafficMonitor::GetPacketHistory(const std::string& key) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    auto it = packet_history_.find(key);
    if (it != packet_history_.end()) {
        return it->second;
    }
    return {};
}

NetEngine::NetEngine() {
    // Initialize Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    // Start WinDivert traffic monitor
    // Start WinDivert traffic monitor
    TrafficMonitor::Instance().Start();
    
    // Initial population of IP->Adapter cache
    UpdateIpToAdapterCache();
}

NetEngine::~NetEngine() {
    TrafficMonitor::Instance().Stop();
    WSACleanup();
}

void NetEngine::UpdateIpToAdapterCache() {
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
    
    if (pAddresses == nullptr) return;

    DWORD dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);
    
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
        if (pAddresses == nullptr) return;
        dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAddresses, &outBufLen);
    }

    if (dwRetVal == NO_ERROR) {
        // Clear old cache only if we got new data successfully
        // Actually, let's just overwrite/insert, clearing might be safer for removed adapters
        ip_to_adapter_cache_.clear();
        
        PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            // Get Adapter Alias (Friendly Name)
            std::string alias = "Unknown";
            if (pCurrAddresses->FriendlyName) {
                int size = WideCharToMultiByte(CP_UTF8, 0, pCurrAddresses->FriendlyName, -1, nullptr, 0, nullptr, nullptr);
                alias.resize(size - 1);
                WideCharToMultiByte(CP_UTF8, 0, pCurrAddresses->FriendlyName, -1, &alias[0], size, nullptr, nullptr);
            }

            // Iterate Unicast Addresses
            PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
            while (pUnicast) {
                char ipStr[INET6_ADDRSTRLEN];
                void* addrPtr = nullptr;
                
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                    addrPtr = &((struct sockaddr_in*)pUnicast->Address.lpSockaddr)->sin_addr;
                    inet_ntop(AF_INET, addrPtr, ipStr, INET_ADDRSTRLEN);
                } else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
                    addrPtr = &((struct sockaddr_in6*)pUnicast->Address.lpSockaddr)->sin6_addr;
                    inet_ntop(AF_INET6, addrPtr, ipStr, INET6_ADDRSTRLEN);
                }
                
                if (addrPtr) {
                   ip_to_adapter_cache_[std::string(ipStr)] = alias;
                }
                
                pUnicast = pUnicast->Next;
            }
            
            pCurrAddresses = pCurrAddresses->Next;
        }
    }
    
    if (pAddresses) free(pAddresses);
}

std::string NetEngine::GetAdapterNameFromIp(const std::string& ip_str) {
    // ip_str comes as "IP:PORT" or just "IP". We need just IP.
    // Handles [IPv6]:Port and IPv4:Port
    
    std::string ip = ip_str;
    size_t lastColon = ip.find_last_of(':');
    size_t closingBracket = ip.find(']');
    
    // If we have brackets [IPv6]:Port
    if (closingBracket != std::string::npos) {
        // IP is everything inside []
        ip = ip.substr(1, closingBracket - 1);
    } 
    // If standard IPv4:Port (192.168.1.1:80)
    else if (lastColon != std::string::npos) {
        ip = ip.substr(0, lastColon);
    }
    
    // Look up
    auto it = ip_to_adapter_cache_.find(ip);
    if (it != ip_to_adapter_cache_.end()) {
        return it->second;
    }
    
    // Fallback: 0.0.0.0 or 127.0.0.1
    if (ip == "0.0.0.0" || ip == "::") return "All Interfaces";
    if (ip == "127.0.0.1" || ip == "::1") return "Loopback";
    
    return "-";
}

std::string NetEngine::GetProcessName(DWORD pid) {
    // Check cache first
    auto it = process_cache_.find(pid);
    if (it != process_cache_.end()) {
        return it->second;
    }

    // Special cases
    if (pid == 0) {
        process_cache_[pid] = "System Idle Process";
        return "System Idle Process";
    }
    if (pid == 4) {
        process_cache_[pid] = "System";
        return "System";
    }

    // Use CreateToolhelp32Snapshot to get process name
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        process_cache_[pid] = "Unknown";
        return "Unknown";
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                // Convert wide string to narrow string
                int size = WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, nullptr, 0, nullptr, nullptr);
                std::string result(size - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, &result[0], size, nullptr, nullptr);
                
                process_cache_[pid] = result;
                CloseHandle(snapshot);
                return result;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    process_cache_[pid] = "Unknown";
    return "Unknown";
}

std::string NetEngine::IpToString(DWORD ip) {
    struct in_addr addr;
    addr.S_un.S_addr = ip;
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, str, INET_ADDRSTRLEN);
    return std::string(str);
}

std::string NetEngine::TcpStateToString(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED: return "CLOSED";
        case MIB_TCP_STATE_LISTEN: return "LISTENING";
        case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD: return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING: return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default: return "UNKNOWN";
    }
}

std::vector<ConnectionInfo> NetEngine::GetTcpConnections() {
    std::vector<ConnectionInfo> connections;

    // First call to get the size
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    // Allocate buffer
    std::vector<BYTE> buffer(size);
    PMIB_TCPTABLE_OWNER_PID tcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

    // Second call to get the actual data
    if (GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID& row = tcpTable->table[i];

            ConnectionInfo info;
            info.process_name = GetProcessName(row.dwOwningPid);
            info.pid = row.dwOwningPid;
            info.protocol = "TCPv4";

            // Local address and port
            std::string localIp = IpToString(row.dwLocalAddr);
            DWORD localPort = ntohs((WORD)row.dwLocalPort);
            info.local_addr = localIp + ":" + std::to_string(localPort);

            // Remote address and port
            std::string remoteIp = IpToString(row.dwRemoteAddr);
            DWORD remotePort = ntohs((WORD)row.dwRemotePort);
            info.remote_addr = remoteIp + ":" + std::to_string(remotePort);

            // State
            info.state = TcpStateToString(row.dwState);
            
            // Get Adapter Name
            info.adapter_name = GetAdapterNameFromIp(info.local_addr);

            // Create key matching WinDivert format: local->remote
            std::string key = info.local_addr + "->" + info.remote_addr;
            
            auto& monitor = TrafficMonitor::Instance();
            info.bytes_sent = monitor.GetSentBytes(key);
            info.bytes_received = monitor.GetReceivedBytes(key);
            info.packets_sent = monitor.GetSentPackets(key);
            info.packets_received = monitor.GetReceivedPackets(key);

            connections.push_back(info);
        }
    }

    return connections;
}

std::vector<ConnectionInfo> NetEngine::GetUdpConnections() {
    std::vector<ConnectionInfo> connections;

    // First call to get the size
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);

    // Allocate buffer
    std::vector<BYTE> buffer(size);
    PMIB_UDPTABLE_OWNER_PID udpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());

    // Second call to get the actual data
    if (GetExtendedUdpTable(udpTable, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
            MIB_UDPROW_OWNER_PID& row = udpTable->table[i];

            ConnectionInfo info;
            info.process_name = GetProcessName(row.dwOwningPid);
            info.pid = row.dwOwningPid;
            info.protocol = "UDPv4";

            // Local address and port
            std::string localIp = IpToString(row.dwLocalAddr);
            DWORD localPort = ntohs((WORD)row.dwLocalPort);
            info.local_addr = localIp + ":" + std::to_string(localPort);

            // UDP has no remote address/port or state
            info.remote_addr = "*:*";
            info.state = "-";
            
            // Get Adapter Name
            info.adapter_name = GetAdapterNameFromIp(info.local_addr);

            // UDP stats
            std::string key = info.local_addr + "->*:*";
            auto& monitor = TrafficMonitor::Instance();
            
            info.bytes_sent = monitor.GetSentBytes(key);
            info.bytes_received = monitor.GetReceivedBytes(key);
            info.packets_sent = monitor.GetSentPackets(key);
            info.packets_received = monitor.GetReceivedPackets(key);

            connections.push_back(info);
        }
    }

    return connections;
}

std::string NetEngine::Ipv6ToString(const BYTE* ipv6) {
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ipv6, str, INET6_ADDRSTRLEN);
    return std::string(str);
}

std::vector<ConnectionInfo> NetEngine::GetTcp6Connections() {
    std::vector<ConnectionInfo> connections;

    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);

    std::vector<BYTE> buffer(size);
    PMIB_TCP6TABLE_OWNER_PID tcpTable = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(buffer.data());

    if (GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            MIB_TCP6ROW_OWNER_PID& row = tcpTable->table[i];

            ConnectionInfo info;
            info.process_name = GetProcessName(row.dwOwningPid);
            info.pid = row.dwOwningPid;
            info.protocol = "TCPv6";

            std::string localIp = Ipv6ToString(row.ucLocalAddr);
            DWORD localPort = ntohs((WORD)row.dwLocalPort);
            info.local_addr = "[" + localIp + "]:" + std::to_string(localPort);

            std::string remoteIp = Ipv6ToString(row.ucRemoteAddr);
            DWORD remotePort = ntohs((WORD)row.dwRemotePort);
            info.remote_addr = "[" + remoteIp + "]:" + std::to_string(remotePort);

            info.state = TcpStateToString(row.dwState);
            
            // Get Adapter Name
            info.adapter_name = GetAdapterNameFromIp(info.local_addr);

            std::string key = info.local_addr + "->" + info.remote_addr;
            auto& monitor = TrafficMonitor::Instance();
            info.bytes_sent = monitor.GetSentBytes(key);
            info.bytes_received = monitor.GetReceivedBytes(key);
            info.packets_sent = monitor.GetSentPackets(key);
            info.packets_received = monitor.GetReceivedPackets(key);

            connections.push_back(info);
        }
    }

    return connections;
}

std::vector<ConnectionInfo> NetEngine::GetUdp6Connections() {
    std::vector<ConnectionInfo> connections;

    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);

    std::vector<BYTE> buffer(size);
    PMIB_UDP6TABLE_OWNER_PID udpTable = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(buffer.data());

    if (GetExtendedUdpTable(udpTable, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
            MIB_UDP6ROW_OWNER_PID& row = udpTable->table[i];

            ConnectionInfo info;
            info.process_name = GetProcessName(row.dwOwningPid);
            info.pid = row.dwOwningPid;
            info.protocol = "UDPv6";

            std::string localIp = Ipv6ToString(row.ucLocalAddr);
            DWORD localPort = ntohs((WORD)row.dwLocalPort);
            info.local_addr = "[" + localIp + "]:" + std::to_string(localPort);

            info.remote_addr = "*:*";
            info.state = "-";
            
            // Get Adapter Name
            info.adapter_name = GetAdapterNameFromIp(info.local_addr);

            std::string key = info.local_addr + "->*:*";
            auto& monitor = TrafficMonitor::Instance();
            info.bytes_sent = monitor.GetSentBytes(key);
            info.bytes_received = monitor.GetReceivedBytes(key);
            info.packets_sent = monitor.GetSentPackets(key);
            info.packets_received = monitor.GetReceivedPackets(key);

            connections.push_back(info);
        }
    }

    return connections;
}

std::vector<ConnectionInfo> NetEngine::GetAllConnections() {
    std::vector<ConnectionInfo> all_connections;

    // Get TCP connections (v4 and v6)
    auto tcp = GetTcpConnections();
    auto tcp6 = GetTcp6Connections();
    
    static bool first_call = true;
    if (first_call) {
        printf("[DEBUG] TCPv4: %zu, TCPv6: %zu\n", tcp.size(), tcp6.size());
    }
    
    // Refresh adapter IP map occasionally (every 10 secs is enough)
    static auto last_ip_map_refresh = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - last_ip_map_refresh).count() >= 10) {
        UpdateIpToAdapterCache();
        last_ip_map_refresh = std::chrono::steady_clock::now();
    }
    
    all_connections.insert(all_connections.end(), tcp.begin(), tcp.end());
    all_connections.insert(all_connections.end(), tcp6.begin(), tcp6.end());

    // Get UDP connections (v4 and v6)
    auto udp = GetUdpConnections();
    auto udp6 = GetUdp6Connections();
    
    if (first_call) {
        printf("[DEBUG] UDPv4: %zu, UDPv6: %zu\n", udp.size(), udp6.size());
        printf("[DEBUG] Total: %zu connections\n", tcp.size() + tcp6.size() + udp.size() + udp6.size());
        first_call = false;
    }
    
    all_connections.insert(all_connections.end(), udp.begin(), udp.end());
    all_connections.insert(all_connections.end(), udp6.begin(), udp6.end());
    
    // Filter out closed/useless connections:
    // - TIME_WAIT: already closed, waiting to expire
    // - CLOSE_WAIT: closing
    // - PID 0: system sockets without process binding
    all_connections.erase(
        std::remove_if(all_connections.begin(), all_connections.end(),
            [](const ConnectionInfo& conn) {
                return conn.state == "TIME_WAIT" || 
                       conn.state == "CLOSE_WAIT" ||
                       conn.pid == 0;
            }
        ),
        all_connections.end()
    );
    
    // Periodically cleanup old connections (every 5 seconds)
    // This removes data for connections that are no longer in the active list
    static auto last_cleanup = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now - last_cleanup).count() >= 5) {
        // Collect all current connection keys (even if they have no traffic)
        std::vector<std::string> active_keys;
        active_keys.reserve(all_connections.size());
        for (const auto& conn : all_connections) {
            active_keys.push_back(conn.local_addr + "->" + conn.remote_addr);
        }
        
        // Cleanup removes data for connections that:
        // - Are no longer in the active list (closed)
        // - Had traffic before (were actively transmitting)
        TrafficMonitor::Instance().CleanupOldConnections(active_keys);
        last_cleanup = now;
    }

    // DEBUG: Check what's actually in the final list
    static bool checked_final = false;
    if (!checked_final) {
        int tcp_count = 0, udp_count = 0;
        for (const auto& conn : all_connections) {
            if (conn.protocol.find("TCP") != std::string::npos) tcp_count++;
            else if (conn.protocol.find("UDP") != std::string::npos) udp_count++;
        }
        printf("[DEBUG FINAL] TCP in list: %d, UDP in list: %d, Total in list: %zu\n", 
               tcp_count, udp_count, all_connections.size());
        checked_final = true;
    }

    return all_connections;
}

std::vector<std::string> NetEngine::GetAdapters() {
    std::vector<std::string> adapters;
    PMIB_IF_TABLE2 table = nullptr;
    
    if (GetIfTable2(&table) == NO_ERROR) {
        for (DWORD i = 0; i < table->NumEntries; i++) {
            MIB_IF_ROW2& row = table->Table[i];
            
            // Skip loopback and disconnected interfaces
            if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK || 
                row.OperStatus != IfOperStatusUp) {
                continue;
            }

            // Convert using WideCharToMultiByte for proper UTF-8
            int size = WideCharToMultiByte(CP_UTF8, 0, row.Alias, -1, nullptr, 0, nullptr, nullptr);
            std::string alias(size - 1, 0);
            WideCharToMultiByte(CP_UTF8, 0, row.Alias, -1, &alias[0], size, nullptr, nullptr);
            
            // Skip technical/system duplicate adapters
            std::string alias_lower = alias;
            std::transform(alias_lower.begin(), alias_lower.end(), alias_lower.begin(), ::tolower);
            if (alias_lower.find("wfp") != std::string::npos ||
                alias_lower.find("filter") != std::string::npos ||
                alias_lower.find("qos") != std::string::npos ||
                alias_lower.find("miniport") != std::string::npos) {
                continue;
            }
            
            adapters.push_back(alias);
        }
        FreeMibTable(table);
    }
    return adapters;
}

NetEngine::AdapterStats NetEngine::GetEthernetStats(const std::string& specific_alias) {
    AdapterStats stats = {};
    PMIB_IF_TABLE2 table = nullptr;
    
    if (GetIfTable2(&table) == NO_ERROR) {
        MIB_IF_ROW2* best_row = nullptr;
        uint64_t max_traffic = 0;

        for (DWORD i = 0; i < table->NumEntries; i++) {
            MIB_IF_ROW2& row = table->Table[i];
            
            // Skip loopback and disconnected interfaces
            if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK || 
                row.OperStatus != IfOperStatusUp) {
                continue;
            }

            // Get alias for check (Use UTF-8)
            int size = WideCharToMultiByte(CP_UTF8, 0, row.Alias, -1, nullptr, 0, nullptr, nullptr);
            std::string alias_str(size - 1, 0);
            WideCharToMultiByte(CP_UTF8, 0, row.Alias, -1, &alias_str[0], size, nullptr, nullptr);

            // Skip technical/system duplicate adapters to avoid confusion
            // These usually just mirror the traffic of the real adapter
            std::string alias_lower = alias_str;
            std::transform(alias_lower.begin(), alias_lower.end(), alias_lower.begin(), ::tolower);
            if (alias_lower.find("wfp") != std::string::npos ||
                alias_lower.find("filter") != std::string::npos ||
                alias_lower.find("qos") != std::string::npos ||
                alias_lower.find("miniport") != std::string::npos) {
                
                // Only skip if we are NOT specifically looking for this one by name
                if (specific_alias.empty()) {
                    continue;
                }
            }

            // If specific alias requested, check match
            if (!specific_alias.empty()) {
                if (alias_str == specific_alias) {
                    best_row = &row;
                    break;
                }
                continue; 
            }

            // AUTO SELECTION LOGIC
        }

        // If no specific alias was requested, try to find the "Internet" adapter via routing table
        if (specific_alias.empty()) {
             DWORD bestIfIndex = 0;
             // Ask Windows: "Which interface helps me reach 8.8.8.8?" (Google DNS)
             // inet_addr("8.8.8.8") = 0x08080808
             if (GetBestInterface(0x08080808, &bestIfIndex) == NO_ERROR) {
                 for (DWORD i = 0; i < table->NumEntries; i++) {
                     if (table->Table[i].InterfaceIndex == bestIfIndex) {
                         best_row = &table->Table[i];
                         break;
                     }
                 }
             }

             // Fallback: If GetBestInterface failed or returned nothing useful, use Max Traffic heuristic
             if (best_row == nullptr) {
                 uint64_t max_traffic = 0;
                 for (DWORD i = 0; i < table->NumEntries; i++) {
                     MIB_IF_ROW2& row = table->Table[i];
                     if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK || row.OperStatus != IfOperStatusUp) continue;
                     
                     // Skip technical/system duplicate adapters
                     int size = WideCharToMultiByte(CP_UTF8, 0, row.Alias, -1, nullptr, 0, nullptr, nullptr);
                     std::string alias(size - 1, 0);
                     WideCharToMultiByte(CP_UTF8, 0, row.Alias, -1, &alias[0], size, nullptr, nullptr);
                     std::string alias_lower = alias;
                     std::transform(alias_lower.begin(), alias_lower.end(), alias_lower.begin(), ::tolower);
                     if (alias_lower.find("wfp") != std::string::npos || alias_lower.find("filter") != std::string::npos ||
                         alias_lower.find("qos") != std::string::npos || alias_lower.find("miniport") != std::string::npos) continue;

                     uint64_t traffic = row.InOctets + row.OutOctets;
                     if (traffic > max_traffic) {
                         max_traffic = traffic;
                         best_row = &row;
                     }
                 }
             }
        }

        if (best_row) {
             // Convert WCHAR Alias to String (UTF-8)
            int size = WideCharToMultiByte(CP_UTF8, 0, best_row->Alias, -1, nullptr, 0, nullptr, nullptr);
            std::string alias(size - 1, 0);
            WideCharToMultiByte(CP_UTF8, 0, best_row->Alias, -1, &alias[0], size, nullptr, nullptr);
            
            stats.alias = alias;

            stats.recv_bytes = best_row->InOctets;
            stats.sent_bytes = best_row->OutOctets;
            stats.recv_packets = best_row->InUcastPkts + best_row->InNUcastPkts;
            stats.sent_packets = best_row->OutUcastPkts + best_row->OutNUcastPkts;
            stats.ReceivedPacketErrors = best_row->InErrors;
            stats.OutboundPacketErrors = best_row->OutErrors;
            stats.ReceivedDiscardedPackets = best_row->InDiscards;
            stats.OutboundDiscardedPackets = best_row->OutDiscards;
        }
        
        FreeMibTable(table);
    }
    return stats;
}
