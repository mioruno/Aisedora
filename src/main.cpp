#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "net_engine.h"
#include "pktmon_dialog.h"

#include <GLFW/glfw3.h>
#include <vector>
#include <chrono>
#include <algorithm>

// Global data
static std::vector<ConnectionInfo> g_connections;
static NetEngine g_net_engine;
static auto g_last_refresh = std::chrono::steady_clock::now();
static const int REFRESH_INTERVAL_MS = 1000; // Refresh every 1 second

// Sorting state
static int g_sort_column = 10; // Default: Recv (Bytes)
static ImGuiSortDirection g_sort_direction = ImGuiSortDirection_Descending; // Default: High to Low

// Global variables for UI state
static bool g_show_packet_inspector = false;
static std::string g_packet_inspector_key = ""; // Key for TrafficMonitor (ip->ip)
static std::string g_selected_ui_key = "";      // Key for Table Selection (ip->ip:pid)
static ImGuiTextFilter g_filter; // Search filter

static NetEngine::AdapterStats g_eth_stats; // Ethernet stats
static bool g_show_pktmon = false;
static PktmonDialog g_pktmon_dialog;

void ApplySorting() {
    if (g_sort_column == -1) return;
    
    std::sort(g_connections.begin(), g_connections.end(), 
        [](const ConnectionInfo& a, const ConnectionInfo& b) {
            bool ascending = g_sort_direction == ImGuiSortDirection_Ascending;
            
            switch (g_sort_column) {
                case 0: return ascending ? (a.process_name < b.process_name) : (a.process_name > b.process_name);
                case 1: return ascending ? (a.pid < b.pid) : (a.pid > b.pid);
                case 2: return ascending ? (a.protocol < b.protocol) : (a.protocol > b.protocol);
                case 3: return ascending ? (a.local_addr < b.local_addr) : (a.local_addr > b.local_addr);
                case 4: return ascending ? (a.adapter_name < b.adapter_name) : (a.adapter_name > b.adapter_name);
                case 5: return ascending ? (a.remote_addr < b.remote_addr) : (a.remote_addr > b.remote_addr);
                case 6: return ascending ? (a.state < b.state) : (a.state > b.state);
                case 7: return ascending ? (a.packets_sent < b.packets_sent) : (a.packets_sent > b.packets_sent);
                case 8: return ascending ? (a.packets_received < b.packets_received) : (a.packets_received > b.packets_received);
                case 9: return ascending ? (a.bytes_sent < b.bytes_sent) : (a.bytes_sent > b.bytes_sent);
                case 10: return ascending ? (a.bytes_received < b.bytes_received) : (a.bytes_received > b.bytes_received);
                default: return false;
            }
        });
}

void RefreshConnectionData() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_last_refresh).count();

    if (elapsed >= REFRESH_INTERVAL_MS) {
        g_connections = g_net_engine.GetAllConnections();
        
        // DEBUG: Check what we got
        static bool first_main_check = true;
        if (first_main_check) {
            int tcp_count = 0, udp_count = 0;
            for (const auto& conn : g_connections) {
                if (conn.protocol.find("TCP") != std::string::npos) tcp_count++;
                else if (conn.protocol.find("UDP") != std::string::npos) udp_count++;
            }
            printf("[MAIN DEBUG] Before sort - TCP: %d, UDP: %d, Total: %zu\n", 
                   tcp_count, udp_count, g_connections.size());
            first_main_check = false;
        }
        
        ApplySorting(); // Apply saved sorting after refresh
        g_last_refresh = now;
    }
}

void RenderUI() {
    // Get the main viewport
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);

    ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoDecoration | 
                                     ImGuiWindowFlags_NoMove | 
                                     ImGuiWindowFlags_NoResize | 
                                     ImGuiWindowFlags_NoSavedSettings |
                                     ImGuiWindowFlags_NoBringToFrontOnFocus;

    ImGui::Begin("Aisedora", nullptr, window_flags);

    // Title and stats
    ImGui::Text("Aisedora - Active Network Connections");
    ImGui::Separator();
    ImGui::Text("Total Connections: %zu", g_connections.size());
    ImGui::SameLine();
    
    // Single Row Layout
    if (ImGui::Button("Refresh Now")) {
         g_connections = g_net_engine.GetAllConnections();
         g_eth_stats = g_net_engine.GetEthernetStats();
         g_last_refresh = std::chrono::steady_clock::now();
         ApplySorting();
    }
    
    ImGui::SameLine();
    if (ImGui::Button("Net Diag")) {
        g_show_pktmon = true;
    }
    
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "|");
    ImGui::SameLine();
    
    ImGui::Text("Search:");
    ImGui::SameLine();
    g_filter.Draw("##search", 180.0f);
    
    // Stats removed as per user request
    ImGui::Separator();

    ImGui::Separator();
    
    // Auto-refresh logic (TIMER)
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - g_last_refresh).count() >= REFRESH_INTERVAL_MS) {
        g_connections = g_net_engine.GetAllConnections();
        g_eth_stats = g_net_engine.GetEthernetStats(); // Update stats automatically
        
        ApplySorting();
        g_last_refresh = now;
    }

    // Table
    ImGuiTableFlags table_flags = ImGuiTableFlags_Borders | 
                                   ImGuiTableFlags_RowBg | 
                                   ImGuiTableFlags_Resizable | 
                                   ImGuiTableFlags_Sortable |
                                   ImGuiTableFlags_ScrollY |
                                   ImGuiTableFlags_SizingStretchProp;
    
    // Smooth Scrolling Logic (PRE-TABLE) to avoid Clipper desync
    // -----------------------------------------------------------------
    static float s_scroll_target = 0.0f;
    static float s_scroll_current = 0.0f;
    static float s_scroll_max = 0.0f; // Saved from last frame
    
    // Handle Input
    if (ImGui::IsWindowHovered(ImGuiHoveredFlags_ChildWindows | ImGuiHoveredFlags_RootAndChildWindows)) {
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0.0f) {
            s_scroll_target -= wheel * 100.0f;
            if (s_scroll_target < 0.0f) s_scroll_target = 0.0f;
            if (s_scroll_target > s_scroll_max) s_scroll_target = s_scroll_max;
        }
    }
    
    // Sync with manual Drag (if we are far off, user dragged the bar)
    // We can't check 'native_scroll' yet because we are before the table.
    // But we can check if the LAST frame's scroll ended up different? 
    // It's tricky pre-table. Let's just trust our interpolation mostly.
    
    // Interpolate
    float dt = ImGui::GetIO().DeltaTime;
    float diff = s_scroll_target - s_scroll_current;
    if (abs(diff) > 0.1f) {
        s_scroll_current += diff * 15.0f * dt;
        // Clamp
        if (s_scroll_current < 0.0f) s_scroll_current = 0.0f; 
        if (s_scroll_current > s_scroll_max) s_scroll_current = s_scroll_max;

        // Apply to the UPCOMING Table Window
        ImGui::SetNextWindowScroll(ImVec2(-1.0f, floorf(s_scroll_current)));
    } else {
        s_scroll_current = s_scroll_target;
    }
    // -----------------------------------------------------------------

    // Increased columns to 11 for "Adapter"
    if (ImGui::BeginTable("ConnectionsTable", 11, table_flags)) {
        // Capture Max Scroll for next frame logic
        s_scroll_max = ImGui::GetScrollMaxY();
        
        // Sync check: If user dragged scrollbar, native scroll will differ from our current.
        // We sync our target to it so we don't snap back.
        if (ImGui::IsItemActive()) { // Is the table being interacted with (scrollbar drag)?
             // Hard to detect specifically scrollbar drag easily without complex logic.
             // We'll skip sync for now to effectively force smooth scroll priority.
        }
        
        // If MouseWheel was 0, and we are not interpolating, sync (handles drag)
         if (ImGui::GetIO().MouseWheel == 0.0f && abs(diff) < 0.1f) {
             float native = ImGui::GetScrollY();
             if (abs(native - s_scroll_current) > 1.0f) {
                 s_scroll_target = native;
                 s_scroll_current = native;
             }
         }

        // Setup columns
        ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthFixed, 160.0f);
        ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("Local Address", ImGuiTableColumnFlags_WidthFixed, 180.0f);
        ImGui::TableSetupColumn("Adapter", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Remote Address", ImGuiTableColumnFlags_WidthFixed, 180.0f);
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Sent (Pkts)", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Recv (Pkts)", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Sent (Bytes)", ImGuiTableColumnFlags_WidthFixed, 110.0f);
        ImGui::TableSetupColumn("Recv (Bytes)", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_PreferSortDescending, 110.0f);
        ImGui::TableSetupScrollFreeze(0, 1); // Freeze header row
        ImGui::TableHeadersRow();

        // Handle sorting
        if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs()) {
            if (sort_specs->SpecsDirty) {
                // Save the sorting state
                if (sort_specs->SpecsCount > 0) {
                    const ImGuiTableColumnSortSpecs& spec = sort_specs->Specs[0];
                    g_sort_column = spec.ColumnIndex;
                    g_sort_direction = spec.SortDirection;
                    ApplySorting();
                }
                sort_specs->SpecsDirty = false;
            }
        }

        // Render rows
        for (const auto& conn : g_connections) {
            // Apply Search Filter (checks process name, PID, addresses)
            std::string search_text = conn.process_name + " " + std::to_string(conn.pid) + " " + conn.local_addr + " " + conn.remote_addr;
            if (!g_filter.PassFilter(search_text.c_str())) {
                continue;
            }

            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            
            // Make the row selectable and span all columns for context menu
            // We use connection_key() (with PID) for UI selection to handle multiple processes on same port
            std::string label = conn.process_name + "##" + conn.connection_key();
            bool is_selected = (g_selected_ui_key == conn.connection_key());
            
            if (ImGui::Selectable(label.c_str(), is_selected, ImGuiSelectableFlags_SpanAllColumns)) {
                g_selected_ui_key = conn.connection_key(); 
            }
            
            // Context Menu logic (Right-Click ANYWHERE on row)
            if (ImGui::BeginPopupContextItem()) {
                if (ImGui::MenuItem("Open Packets")) {
                    g_show_packet_inspector = true;
                    // Fix: Use the format "local->remote" matching WinDivert (no PID)
                    g_packet_inspector_key = conn.local_addr + "->" + conn.remote_addr;
                }
                ImGui::EndPopup();
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%lu", conn.pid);

            ImGui::TableSetColumnIndex(2);
            // Display actual protocol with color coding
            if (conn.protocol.find("TCP") != std::string::npos) {
                ImGui::TextColored(ImVec4(0.3f, 0.8f, 0.3f, 1.0f), "%s", conn.protocol.c_str());
            } else {
                ImGui::TextColored(ImVec4(0.3f, 0.6f, 1.0f, 1.0f), "%s", conn.protocol.c_str());
            }

            ImGui::TableSetColumnIndex(3);
            ImGui::Text("%s", conn.local_addr.c_str());

            ImGui::TableSetColumnIndex(4);
            // Show Adapter Name (Truncate if too long maybe?)
            ImGui::Text("%s", conn.adapter_name.c_str());

            ImGui::TableSetColumnIndex(5);
            ImGui::Text("%s", conn.remote_addr.c_str());

            ImGui::TableSetColumnIndex(6);
            // Color code state
            if (conn.state == "ESTABLISHED") {
                ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f), "%s", conn.state.c_str());
            } else if (conn.state == "LISTENING") {
                ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.3f, 1.0f), "%s", conn.state.c_str());
            } else if (conn.state == "CLOSE_WAIT" || conn.state == "TIME_WAIT") {
                ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.3f, 1.0f), "%s", conn.state.c_str());
            } else {
                ImGui::Text("%s", conn.state.c_str());
            }
            
            // Packet statistics
            ImGui::TableSetColumnIndex(7);
            if (conn.packets_sent > 0) {
                ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.4f, 1.0f), "%llu", conn.packets_sent);
            } else {
                ImGui::Text("0");
            }
            
            ImGui::TableSetColumnIndex(8);
            if (conn.packets_received > 0) {
                ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "%llu", conn.packets_received);
            } else {
                ImGui::Text("0");
            }
            
            // Byte statistics (counted from app start)
            ImGui::TableSetColumnIndex(9);
            if (conn.bytes_sent > 0) {
                ImGui::TextColored(ImVec4(1.0f, 0.7f, 0.3f, 1.0f), "%llu", conn.bytes_sent);
            } else {
                ImGui::Text("0");
            }
            
            ImGui::TableSetColumnIndex(10);
            if (conn.bytes_received > 0) {
                ImGui::TextColored(ImVec4(0.3f, 0.7f, 1.0f, 1.0f), "%llu", conn.bytes_received);
            }
        }

        ImGui::EndTable();
    }

    ImGui::End();
}

void RenderPacketInspector() {
    if (!g_show_packet_inspector) return;

    ImGui::SetNextWindowSize(ImVec2(600, 400), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Packet Inspector", &g_show_packet_inspector)) {
        ImGui::Text("Connection: %s", g_packet_inspector_key.c_str());
        ImGui::Separator();
        
        static ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV | ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable;
        
        if (ImGui::BeginTable("PacketsTable", 5, flags)) {
            ImGui::TableSetupColumn("Time");
            ImGui::TableSetupColumn("Dir");
            ImGui::TableSetupColumn("Size");
            ImGui::TableSetupColumn("Flags");
            ImGui::TableSetupColumn("Payload");
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();

            // Fetch packets
            auto packets = TrafficMonitor::Instance().GetPacketHistory(g_packet_inspector_key);
            
            // Reverse packets to show newest at top
            std::reverse(packets.begin(), packets.end());
            
            // DISABLED: Auto-scroll caused annoying teleportation
            // if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
            //    ImGui::SetScrollHereY(1.0f);

            for (const auto& pkt : packets) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("%s", pkt.timestamp.c_str());
                
                ImGui::TableSetColumnIndex(1);
                if (pkt.outbound) ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.4f, 1.0f), "OUT");
                else ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "IN");
                
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%u", pkt.size);
                
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%s", pkt.flags.c_str());
                
                ImGui::TableSetColumnIndex(4);
                ImGui::Text("%s", pkt.payload_preview.c_str());
            }
            ImGui::EndTable();
        }
    }
    ImGui::End();
}

int main(int argc, char** argv) {
    // Initialize GLFW
    if (!glfwInit()) {
        return -1;
    }

    // GL 3.0 + GLSL 130
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    // Create window
    GLFWwindow* window = glfwCreateWindow(1800, 900, "Aisedora - Network Connections Monitor", nullptr, nullptr);
    if (window == nullptr) {
        glfwTerminate();
        return -1;
    }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // Load modern font (Segoe UI from Windows)
    ImFontConfig fontConfig;
    fontConfig.OversampleH = 3;
    fontConfig.OversampleV = 3;
    fontConfig.PixelSnapH = true; // Fix for blurry/smearing text during motion
    
    // Try to load Segoe UI (modern Windows font)
    ImFont* font = io.Fonts->AddFontFromFileTTF(
        "C:\\Windows\\Fonts\\segoeui.ttf", 
        18.0f,  // Font size
        &fontConfig,
        io.Fonts->GetGlyphRangesCyrillic()  // Support for Cyrillic
    );
    
    // Fallback to default font if Segoe UI not found
    if (!font) {
        fontConfig.SizePixels = 16.0f;
        io.Fonts->AddFontDefault(&fontConfig);
    }
    
    io.Fonts->Build();

    // Setup Dear ImGui style
    ImGui::StyleColorsDark();

    // Customize style for better appearance
    ImGuiStyle& style = ImGui::GetStyle();
    
    // Modern Geometry
    style.WindowRounding = 8.0f;
    style.ChildRounding = 8.0f;
    style.FrameRounding = 6.0f;
    style.GrabRounding = 6.0f;
    style.PopupRounding = 8.0f;
    style.ScrollbarRounding = 12.0f;
    style.TabRounding = 6.0f;
    
    style.WindowPadding = ImVec2(15, 15);
    style.FramePadding = ImVec2(10, 6);
    style.ItemSpacing = ImVec2(10, 8);
    style.ScrollbarSize = 14.0f;
    style.IndentSpacing = 20.0f;

    // Modern Dark Color Palette
    ImVec4* colors = style.Colors;
    colors[ImGuiCol_Text]                   = ImVec4(0.95f, 0.96f, 0.98f, 1.00f);
    colors[ImGuiCol_TextDisabled]           = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
    colors[ImGuiCol_WindowBg]               = ImVec4(0.12f, 0.12f, 0.14f, 1.00f); // Darker background
    colors[ImGuiCol_ChildBg]                = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_PopupBg]                = ImVec4(0.15f, 0.15f, 0.17f, 0.98f);
    colors[ImGuiCol_Border]                 = ImVec4(0.25f, 0.25f, 0.28f, 0.50f);
    colors[ImGuiCol_BorderShadow]           = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]                = ImVec4(0.20f, 0.21f, 0.24f, 0.54f);
    colors[ImGuiCol_FrameBgHovered]         = ImVec4(0.24f, 0.25f, 0.29f, 0.60f);
    colors[ImGuiCol_FrameBgActive]          = ImVec4(0.28f, 0.29f, 0.33f, 0.70f);
    colors[ImGuiCol_TitleBg]                = ImVec4(0.12f, 0.12f, 0.14f, 1.00f);
    colors[ImGuiCol_TitleBgActive]          = ImVec4(0.12f, 0.12f, 0.14f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed]       = ImVec4(0.12f, 0.12f, 0.14f, 0.51f);
    colors[ImGuiCol_MenuBarBg]              = ImVec4(0.15f, 0.15f, 0.17f, 1.00f);
    colors[ImGuiCol_ScrollbarBg]            = ImVec4(0.12f, 0.12f, 0.14f, 0.53f);
    colors[ImGuiCol_ScrollbarGrab]          = ImVec4(0.31f, 0.31f, 0.31f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered]   = ImVec4(0.41f, 0.41f, 0.41f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive]    = ImVec4(0.51f, 0.51f, 0.51f, 1.00f);
    colors[ImGuiCol_CheckMark]              = ImVec4(0.40f, 0.60f, 1.00f, 1.00f); // Blue accent
    colors[ImGuiCol_SliderGrab]             = ImVec4(0.36f, 0.55f, 0.89f, 1.00f);
    colors[ImGuiCol_SliderGrabActive]       = ImVec4(0.40f, 0.60f, 1.00f, 1.00f);
    colors[ImGuiCol_Button]                 = ImVec4(0.22f, 0.24f, 0.28f, 1.00f);
    colors[ImGuiCol_ButtonHovered]          = ImVec4(0.26f, 0.28f, 0.33f, 1.00f);
    colors[ImGuiCol_ButtonActive]           = ImVec4(0.20f, 0.22f, 0.25f, 1.00f);
    colors[ImGuiCol_Header]                 = ImVec4(0.22f, 0.24f, 0.28f, 1.00f); // Table Header
    colors[ImGuiCol_HeaderHovered]          = ImVec4(0.26f, 0.28f, 0.33f, 1.00f);
    colors[ImGuiCol_HeaderActive]           = ImVec4(0.20f, 0.22f, 0.25f, 1.00f);
    colors[ImGuiCol_Separator]              = ImVec4(0.25f, 0.25f, 0.28f, 1.00f);
    colors[ImGuiCol_SeparatorHovered]       = ImVec4(0.10f, 0.40f, 0.75f, 0.78f);
    colors[ImGuiCol_SeparatorActive]        = ImVec4(0.10f, 0.40f, 0.75f, 1.00f);
    colors[ImGuiCol_ResizeGrip]             = ImVec4(0.26f, 0.59f, 0.98f, 0.25f);
    colors[ImGuiCol_ResizeGripHovered]      = ImVec4(0.26f, 0.59f, 0.98f, 0.67f);
    colors[ImGuiCol_ResizeGripActive]       = ImVec4(0.26f, 0.59f, 0.98f, 0.95f);
    colors[ImGuiCol_Tab]                    = ImVec4(0.18f, 0.35f, 0.58f, 0.86f);
    colors[ImGuiCol_TabHovered]             = ImVec4(0.26f, 0.59f, 0.98f, 0.80f);
    colors[ImGuiCol_TabActive]              = ImVec4(0.20f, 0.41f, 0.68f, 1.00f);
    colors[ImGuiCol_TabUnfocused]           = ImVec4(0.07f, 0.10f, 0.15f, 0.97f);
    colors[ImGuiCol_TabUnfocusedActive]     = ImVec4(0.14f, 0.26f, 0.42f, 1.00f);
    colors[ImGuiCol_PlotLines]              = ImVec4(0.61f, 0.61f, 0.61f, 1.00f);
    colors[ImGuiCol_PlotLinesHovered]       = ImVec4(1.00f, 0.43f, 0.35f, 1.00f);
    colors[ImGuiCol_PlotHistogram]          = ImVec4(0.90f, 0.70f, 0.00f, 1.00f);
    colors[ImGuiCol_PlotHistogramHovered]   = ImVec4(1.00f, 0.60f, 0.00f, 1.00f);
    colors[ImGuiCol_TableHeaderBg]          = ImVec4(0.19f, 0.19f, 0.20f, 1.00f);
    colors[ImGuiCol_TableBorderStrong]      = ImVec4(0.31f, 0.31f, 0.35f, 1.00f);   // 
    colors[ImGuiCol_TableBorderLight]       = ImVec4(0.23f, 0.23f, 0.25f, 1.00f);   // 
    colors[ImGuiCol_TableRowBg]             = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_TableRowBgAlt]          = ImVec4(1.00f, 1.00f, 1.00f, 0.03f); // Subtle stripe
    colors[ImGuiCol_TextSelectedBg]         = ImVec4(0.26f, 0.59f, 0.98f, 0.35f);
    colors[ImGuiCol_DragDropTarget]         = ImVec4(1.00f, 1.00f, 0.00f, 0.90f);
    colors[ImGuiCol_NavHighlight]           = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
    colors[ImGuiCol_NavWindowingHighlight]  = ImVec4(1.00f, 1.00f, 1.00f, 0.70f);
    colors[ImGuiCol_NavWindowingDimBg]      = ImVec4(0.80f, 0.80f, 0.80f, 0.20f);
    colors[ImGuiCol_ModalWindowDimBg]       = ImVec4(0.80f, 0.80f, 0.80f, 0.35f);

    // Setup Platform/Renderer backends
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Initial data fetch
    g_connections = g_net_engine.GetAllConnections();
    g_eth_stats = g_net_engine.GetEthernetStats(); // Initial fetch
    g_last_refresh = std::chrono::steady_clock::now();

    // Background color
    ImVec4 clear_color = ImVec4(0.1f, 0.1f, 0.1f, 1.0f);

    // Forward declaration    
    void RenderPacketInspector(); 

    // Main loop
    while (!glfwWindowShouldClose(window)) {
        // Poll events
        glfwPollEvents();

        // Refresh connection data (throttled to 1 second)
        RefreshConnectionData();

        // Start ImGui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // Render our UI
        RenderUI();
        RenderPacketInspector(); // Show packet window if active
        g_pktmon_dialog.Render(&g_show_pktmon); // Pktmon Dialog

        // Rendering
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(clear_color.x, clear_color.y, clear_color.z, clear_color.w);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
