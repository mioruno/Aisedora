#include "pktmon_dialog.h"
#include "imgui.h"
#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <string>
#include <chrono>
#include <ctime>

void PktmonDialog::Render(bool* p_open) {
    if (!*p_open) return;

    ImGui::SetNextWindowSize(ImVec2(500, 500), ImGuiCond_FirstUseEver); // Increased size for logs
    if (ImGui::Begin("Network Diagnostic (Pktmon)", p_open)) {
        
        ImGui::Text("Windows Packet Monitor Wrapper");
        ImGui::Separator();
        
        // Settings Group
        ImGui::BeginGroup();
        ImGui::InputInt("Port", &port);
        
        if (ImGui::Checkbox("TCP", &is_tcp)) {
             if (is_tcp) is_udp = false;
        }
        ImGui::SameLine();
        if (ImGui::Checkbox("UDP", &is_udp)) {
             if (is_udp) is_tcp = false;
        }
        if (!is_tcp && !is_udp) is_tcp = true;
        ImGui::EndGroup();

        ImGui::Spacing();
        
        // Actions
        if (is_capturing) {
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "CAPTURE IN PROGRESS... (Checks nics)");
            if (ImGui::Button("Stop & Save Report", ImVec2(-1, 40))) {
                StopCapture();
            }
        } else {
            ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "Ready (Requires Admin)");
            if (ImGui::Button("Start Capture", ImVec2(-1, 40))) {
                StartCapture();
            }
        }
        
        ImGui::Separator();
        ImGui::Text("Execution Log:");
        
        // Log Window
        ImGui::BeginChild("LogRegion", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
        for (const auto& log : logs) {
            // Colorize specific keywords for better readability
            if (log.find("[CMD]") != std::string::npos) {
                ImGui::TextColored(ImVec4(0.5f, 0.8f, 1.0f, 1.0f), "%s", log.c_str());
            } 
            else if (log.find("[SUCCESS]") != std::string::npos) {
                ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "%s", log.c_str());
            }
            else if (log.find("[ERROR]") != std::string::npos) {
                ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", log.c_str());
            }
            else {
                ImGui::Text("%s", log.c_str());
            }
        }
        
        // Auto-scroll to bottom
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
            ImGui::SetScrollHereY(1.0f);
            
        ImGui::EndChild();

        ImGui::End();
    }
}

void PktmonDialog::AddLog(const std::string& msg) {
    // Add timestamp
    std::time_t now = std::time(nullptr);
    char buf[100];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&now));
    
    logs.push_back(std::string("[") + buf + "] " + msg);
}

void PktmonDialog::StartCapture() {
    logs.clear();
    AddLog("Initializing capture session...");

    // 1. Filter Remove
    RunCommand("pktmon", "filter remove");
    
    // 2. Filter Add
    std::string proto = is_tcp ? "TCP" : "UDP";
    std::string args = "filter add -p " + std::to_string(port) + " -t " + proto;
    AddLog("Setting up filter for Port " + std::to_string(port) + " (" + proto + ")...");
    RunCommand("pktmon", args);
    
    // 3. Start
    AddLog("Starting packet monitor (comp nics)...");
    RunCommand("pktmon", "start --etw --comp nics");
    
    is_capturing = true;
    AddLog("[SUCCESS] Capture is running!");
}

void PktmonDialog::StopCapture() {
    AddLog("Stopping capture...");
    
    // 1. Stop
    RunCommand("pktmon", "stop");
    
    // 2. Format
    std::string desktop = GetDesktopPath();
    if (!desktop.empty()) {
        std::string output = desktop + "\\pktmon_log.txt";
        std::string args = "format PktMon.etl -o \"" + output + "\"";
        
        AddLog("Converting ETL to text format...");
        RunCommand("pktmon", args);
        
        AddLog("[SUCCESS] Report saved to: " + output);
        MessageBoxA(NULL, ("Report saved to:\n" + output).c_str(), "Pktmon Report", MB_OK | MB_ICONINFORMATION);
    } else {
         AddLog("[ERROR] Could not find Desktop path!");
         MessageBoxA(NULL, "Could not find Desktop path!", "Error", MB_OK | MB_ICONERROR);
    }

    is_capturing = false;
}

void PktmonDialog::RunCommand(const std::string& cmd, const std::string& args) {
    AddLog("[CMD] " + cmd + " " + args);
    ShellExecuteA(NULL, "open", cmd.c_str(), args.c_str(), NULL, SW_HIDE);
    Sleep(150); // Slight delay for log visual and command stability
}

std::string PktmonDialog::GetDesktopPath() {
    PWSTR path = NULL;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Desktop, 0, NULL, &path))) {
        char path_utf8[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, path, -1, path_utf8, MAX_PATH, NULL, NULL);
        CoTaskMemFree(path);
        return std::string(path_utf8);
    }
    return "";
}
