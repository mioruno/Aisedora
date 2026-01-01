#pragma once
#include <string>

class PktmonDialog {
public:
    void Render(bool* p_open);

private:
    int port = 443;
    bool is_tcp = true;
    bool is_udp = false;
    bool is_capturing = false;
    
    // Logging
    std::vector<std::string> logs;
    void AddLog(const std::string& msg);

    void StartCapture();
    void StopCapture();
    void RunCommand(const std::string& cmd, const std::string& args);
    std::string GetDesktopPath();
};
