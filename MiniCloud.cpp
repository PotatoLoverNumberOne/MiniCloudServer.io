#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <regex>
#include <vector>
#include <map>
#include <algorithm>
#include <random>
#include <ctime>
#include <iomanip>
#include <iphlpapi.h>
#include <windows.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <conio.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace fs = std::filesystem;

// ========== CONFIGURATION ==========
const int PORT = 8080;
const std::string UPLOAD_DIR = "uploads";
const std::string SESSION_DIR = "sessions";
const unsigned long long FREE_MAX_FILE_SIZE = 100ULL * 1024ULL * 1024ULL; // 100MB
const unsigned long long ADMIN_MAX_FILE_SIZE = 3ULL * 1024ULL * 1024ULL * 1024ULL; // 3GB
const unsigned long long FREE_MAX_TOTAL_UPLOADS = 1ULL * 1024ULL * 1024ULL * 1024ULL; // 1GB
const unsigned long long ADMIN_MAX_TOTAL_UPLOADS = 10ULL * 1024ULL * 1024ULL * 1024ULL; // 10GB
const size_t BUFFER_SIZE = 65536; // Reduced for better stability 65536 KB
// ===================================

// Thread-safe logging
std::mutex log_mutex;
std::atomic<int> total_uploads{ 0 };
std::atomic<int> total_downloads{ 0 };
std::atomic<unsigned long long> total_bandwidth{ 0 };
std::atomic<int> active_connections{ 0 };
std::atomic<bool> server_running{ true };
std::atomic<bool> monitor_mode{ false };

// Safe localtime wrapper
tm* safe_localtime(const time_t* time) {
    static tm result;
    localtime_s(&result, time);
    return &result;
}

// Forward declaration
void safe_log(const std::string& message);

// Session management
struct Session {
    std::string id;
    time_t created;
    time_t last_activity;
    std::string username;
    bool is_admin;

    Session() : created(0), last_activity(0), is_admin(false) {}
    Session(const std::string& id_, time_t created_, time_t last_activity_,
        const std::string& username_, bool admin)
        : id(id_), created(created_), last_activity(last_activity_),
        username(username_), is_admin(admin) {
    }
};

std::map<std::string, Session> active_sessions;
std::mutex session_mutex;

// ========== MONITOR SYSTEM ==========
struct ServerStats {
    int connections;
    int uploads;
    int downloads;
    unsigned long long bandwidth;
    time_t uptime;
    std::vector<std::string> recent_logs;
};

class MonitorSystem {
private:
    std::vector<std::string> log_history;
    std::mutex history_mutex;
    time_t server_start_time;

public:
    MonitorSystem() {
        server_start_time = time(nullptr);
        log_history.reserve(1000);
    }

    void add_log(const std::string& log) {
        std::lock_guard<std::mutex> lock(history_mutex);
        if (log_history.size() >= 1000) {
            log_history.erase(log_history.begin());
        }
        log_history.push_back(log);
    }

    ServerStats get_stats() {
        ServerStats stats;
        stats.connections = active_connections.load();
        stats.uploads = total_uploads.load();
        stats.downloads = total_downloads.load();
        stats.bandwidth = total_bandwidth.load();
        stats.uptime = time(nullptr) - server_start_time;

        {
            std::lock_guard<std::mutex> lock(history_mutex);
            size_t count = 20;
            size_t start_idx = log_history.size() > count ? log_history.size() - count : 0;
            stats.recent_logs.assign(log_history.begin() + start_idx, log_history.end());
        }

        return stats;
    }

    void display_monitor() {
        system("cls");
        std::cout << "==============================================================\n";
        std::cout << "                 MINICLOUD SERVER MONITOR                    \n";
        std::cout << "==============================================================\n";
        std::cout << " [1] Enter Monitor Mode        [2] Exit Monitor Mode        \n";
        std::cout << " [3] Show Detailed Stats       [4] Clear Screen             \n";
        std::cout << " [5] Show Active Sessions      [6] Show Upload Directory    \n";
        std::cout << " [7] Show Recent Logs          [8] Reset Statistics         \n";
        std::cout << " [9] Show Help                 [0] Back to Main Menu        \n";
        std::cout << "==============================================================\n";
        std::cout << " Commands: stats, sessions, logs, clear, help, exit        \n";
        std::cout << "==============================================================\n\n";
    }

    void show_detailed_stats() {
        ServerStats stats = get_stats();

        std::cout << "\n=== DETAILED SERVER STATISTICS ===\n\n";

        // Uptime
        int days = static_cast<int>(stats.uptime / 86400);
        int hours = static_cast<int>((stats.uptime % 86400) / 3600);
        int minutes = static_cast<int>((stats.uptime % 3600) / 60);
        int seconds = static_cast<int>(stats.uptime % 60);
        std::cout << "Uptime: " << days << "d " << hours << "h "
            << minutes << "m " << seconds << "s\n";

        // Connections
        std::cout << "Active Connections: " << stats.connections << "\n";

        // Uploads/Downloads
        std::cout << "Total Uploads: " << stats.uploads << "\n";
        std::cout << "Total Downloads: " << stats.downloads << "\n";

        // Bandwidth
        double bandwidth_mb = stats.bandwidth / (1024.0 * 1024.0);
        double bandwidth_gb = stats.bandwidth / (1024.0 * 1024.0 * 1024.0);
        if (bandwidth_gb >= 1.0) {
            std::cout << "Total Bandwidth: " << std::fixed << std::setprecision(2)
                << bandwidth_gb << " GB\n";
        }
        else {
            std::cout << "Total Bandwidth: " << std::fixed << std::setprecision(2)
                << bandwidth_mb << " MB\n";
        }

        // Upload directory info
        try {
            unsigned long long total_size = 0;
            int file_count = 0;

            for (const auto& entry : fs::directory_iterator(UPLOAD_DIR)) {
                if (fs::is_regular_file(entry.path())) {
                    file_count++;
                    try {
                        total_size += static_cast<unsigned long long>(fs::file_size(entry.path()));
                    }
                    catch (...) {}
                }
            }

            double total_gb = total_size / (1024.0 * 1024.0 * 1024.0);
            std::cout << "Files in Upload Directory: " << file_count << "\n";
            std::cout << "Total Storage Used: " << std::fixed << std::setprecision(2)
                << total_gb << " GB\n";

            // Show storage limits
            std::cout << "\n=== STORAGE LIMITS ===\n";
            std::cout << "Free Tier Max File: 100 MB\n";
            std::cout << "Free Tier Total: 1 GB\n";
            std::cout << "Admin Tier Max File: 3 GB\n";
            std::cout << "Admin Tier Total: 10 GB\n";

        }
        catch (...) {
            std::cout << "Upload directory not accessible\n";
        }

        // Active sessions
        {
            std::lock_guard<std::mutex> lock(session_mutex);
            std::cout << "\nActive Sessions: " << active_sessions.size() << "\n";
        }

        std::cout << "\nPress any key to continue...";
        _getch();
    }

    void show_active_sessions() {
        std::lock_guard<std::mutex> lock(session_mutex);

        std::cout << "\n=== ACTIVE SESSIONS ===\n\n";

        if (active_sessions.empty()) {
            std::cout << "No active sessions\n";
        }
        else {
            std::cout << std::left << std::setw(40) << "Session ID"
                << std::setw(15) << "Username"
                << std::setw(10) << "Admin"
                << std::setw(20) << "Created"
                << std::setw(20) << "Last Activity" << "\n";
            std::cout << std::string(105, '-') << "\n";

            for (const auto& [id, session] : active_sessions) {
                tm* created_tm = safe_localtime(&session.created);
                tm* last_tm = safe_localtime(&session.last_activity);

                char created_buf[20], last_buf[20];
                strftime(created_buf, sizeof(created_buf), "%H:%M:%S", created_tm);
                strftime(last_buf, sizeof(last_buf), "%H:%M:%S", last_tm);

                std::cout << std::left << std::setw(40) << (id.substr(0, 16) + "...")
                    << std::setw(15) << session.username
                    << std::setw(10) << (session.is_admin ? "Yes" : "No")
                    << std::setw(20) << created_buf
                    << std::setw(20) << last_buf << "\n";
            }
        }

        std::cout << "\nPress any key to continue...";
        _getch();
    }

    void show_upload_directory() {
        std::cout << "\n=== UPLOAD DIRECTORY CONTENTS ===\n\n";

        try {
            std::vector<std::tuple<std::string, unsigned long long, time_t>> files;

            for (const auto& entry : fs::directory_iterator(UPLOAD_DIR)) {
                if (fs::is_regular_file(entry.path())) {
                    try {
                        auto filename = entry.path().filename().string();
                        auto size = static_cast<unsigned long long>(fs::file_size(entry.path()));
                        auto mod_time = fs::last_write_time(entry.path());
                        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                            mod_time - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
                        time_t mod_time_t = std::chrono::system_clock::to_time_t(sctp);

                        files.emplace_back(filename, size, mod_time_t);
                    }
                    catch (...) {}
                }
            }

            if (files.empty()) {
                std::cout << "No files in upload directory\n";
            }
            else {
                std::cout << std::left << std::setw(40) << "Filename"
                    << std::setw(15) << "Size"
                    << std::setw(30) << "Last Modified" << "\n";
                std::cout << std::string(85, '-') << "\n";

                for (const auto& [filename, size, mod_time] : files) {
                    tm* mod_tm = safe_localtime(&mod_time);
                    char time_buf[30];
                    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", mod_tm);

                    std::string size_str;
                    if (size < 1024) {
                        size_str = std::to_string(size) + " B";
                    }
                    else if (size < 1024 * 1024) {
                        size_str = std::to_string(size / 1024) + " KB";
                    }
                    else if (size < 1024 * 1024 * 1024) {
                        size_str = std::to_string(size / (1024 * 1024)) + " MB";
                    }
                    else {
                        size_str = std::to_string(size / (1024 * 1024 * 1024)) + " GB";
                    }

                    std::string display_name = filename;
                    if (filename.length() > 37) {
                        display_name = filename.substr(0, 34) + "...";
                    }

                    std::cout << std::left << std::setw(40) << display_name
                        << std::setw(15) << size_str
                        << std::setw(30) << time_buf << "\n";
                }
            }
        }
        catch (const std::exception& e) {
            std::cout << "Error accessing upload directory: " << e.what() << "\n";
        }

        std::cout << "\nPress any key to continue...";
        _getch();
    }

    void show_recent_logs(int count = 20) {
        std::lock_guard<std::mutex> lock(history_mutex);

        std::cout << "\n=== RECENT LOGS ===\n\n";

        if (log_history.empty()) {
            std::cout << "No logs available\n";
        }
        else {
            // Display at most 'count' logs
            size_t start_idx = 0;
            if (log_history.size() > static_cast<size_t>(count)) {
                start_idx = log_history.size() - count;
            }

            for (size_t i = start_idx; i < log_history.size(); i++) {
                std::cout << log_history[i] << "\n";
            }
        }

        std::cout << "\nPress any key to continue...";
        _getch();
    }

    void reset_statistics() {
        total_uploads = 0;
        total_downloads = 0;
        total_bandwidth = 0;

        std::cout << "\nStatistics have been reset.\n";
        std::cout << "Press any key to continue...";
        _getch();
    }

    void show_help() {
        std::cout << "\n=== MONITOR SYSTEM HELP ===\n\n";
        std::cout << "Monitor Mode Commands:\n";
        std::cout << "  stats     - Show detailed server statistics\n";
        std::cout << "  sessions  - Show active user sessions\n";
        std::cout << "  logs      - Show recent server logs\n";
        std::cout << "  clear     - Clear the screen\n";
        std::cout << "  help      - Show this help message\n";
        std::cout << "  exit      - Exit monitor mode\n\n";

        std::cout << "Keyboard Shortcuts:\n";
        std::cout << "  [1] - Enter monitor mode\n";
        std::cout << "  [2] - Exit monitor mode\n";
        std::cout << "  [3] - Show detailed statistics\n";
        std::cout << "  [4] - Clear screen\n";
        std::cout << "  [5] - Show active sessions\n";
        std::cout << "  [6] - Show upload directory contents\n";
        std::cout << "  [7] - Show recent logs\n";
        std::cout << "  [8] - Reset statistics\n";
        std::cout << "  [9] - Show help\n";
        std::cout << "  [0] - Back to main menu\n\n";

        std::cout << "Press any key to continue...";
        _getch();
    }
};

MonitorSystem monitor;

// Safe log function definition
void safe_log(const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex);
    time_t now = time(nullptr);
    tm* local_time = safe_localtime(&now);
    char time_buf[80];
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", local_time);
    std::string full_message = "[" + std::string(time_buf) + "] " + message;
    std::cout << full_message << std::endl;

    // Add to monitor history
    monitor.add_log(full_message);
}

// ========== END MONITOR SYSTEM ==========

// MIME types
std::map<std::string, std::string> mime_types = {
    {".jpg", "image/jpeg"}, {".jpeg", "image/jpeg"}, {".png", "image/png"},
    {".gif", "image/gif"}, {".bmp", "image/bmp"}, {".mp4", "video/mp4"},
    {".mp3", "audio/mpeg"}, {".pdf", "application/pdf"}, {".txt", "text/plain"},
    {".zip", "application/zip"}, {".rar", "application/x-rar-compressed"},
    {".html", "text/html"}, {".css", "text/css"}, {".js", "application/javascript"}
};

// Utility functions
std::string generate_session_id() {
    std::stringstream ss;
    std::random_device rd;
    std::mt19937_64 rng(rd());
    std::uniform_int_distribution<int> dist(0, 255);

    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << dist(rng);
    }
    return ss.str();
}

std::string get_mime_type(const std::string& filename) {
    size_t dot_pos = filename.find_last_of('.');
    if (dot_pos == std::string::npos) return "application/octet-stream";

    std::string ext = filename.substr(dot_pos);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    auto it = mime_types.find(ext);
    if (it != mime_types.end()) return it->second;
    return "application/octet-stream";
}

// HTTP response functions
bool send_all(SOCKET sock, const char* buf, int len) {
    int total_sent = 0;
    while (total_sent < len) {
        int sent = send(sock, buf + total_sent, len - total_sent, 0);
        if (sent <= 0) return false;
        total_sent += sent;
    }
    return true;
}

void send_response(SOCKET client, const std::string& content,
    const std::string& content_type = "text/html",
    const std::string& cookies = "") {

    std::string header = "HTTP/1.1 200 OK\r\n";
    if (!cookies.empty()) header += "Set-Cookie: " + cookies + "\r\n";
    header += "Content-Length: " + std::to_string(content.size()) + "\r\n";
    header += "Content-Type: " + content_type + "\r\n";
    header += "Connection: close\r\n\r\n";

    if (!send_all(client, header.c_str(), static_cast<int>(header.size())) ||
        !send_all(client, content.c_str(), static_cast<int>(content.size()))) {
        safe_log("Failed to send response");
    }
}

void send_redirect(SOCKET client, const std::string& location,
    const std::string& cookies = "") {
    std::string header = "HTTP/1.1 302 Found\r\n";
    if (!cookies.empty()) header += "Set-Cookie: " + cookies + "\r\n";
    header += "Location: " + location + "\r\n";
    header += "Connection: close\r\n\r\n";

    if (!send_all(client, header.c_str(), static_cast<int>(header.size()))) {
        safe_log("Failed to send redirect");
    }
}

void send_error(SOCKET client, int code, const std::string& message) {
    std::string response = "HTTP/1.1 " + std::to_string(code) + " " + message + "\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n\r\n"
        "<h1>" + std::to_string(code) + " " + message + "</h1>";

    send_all(client, response.c_str(), static_cast<int>(response.size()));
}

// Authentication
bool check_authentication(const std::string& request, Session& session) {
    std::regex cookie_regex("Cookie:[^;]*session=([a-f0-9]+)");
    std::smatch match;

    if (std::regex_search(request, match, cookie_regex)) {
        std::string session_id = match[1].str();
        std::lock_guard<std::mutex> lock(session_mutex);
        auto it = active_sessions.find(session_id);
        if (it != active_sessions.end()) {
            time_t now = time(nullptr);
            if (difftime(now, it->second.last_activity) < 3600) { // 1 hour session
                it->second.last_activity = now;
                session = it->second;
                return true;
            }
            else {
                active_sessions.erase(it);
            }
        }
    }
    return false;
}

// Read complete request
std::string read_complete_request(SOCKET client) {
    std::string request;
    char buffer[BUFFER_SIZE];
    int bytes_read;

    // Read headers first
    do {
        bytes_read = recv(client, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            request.append(buffer, bytes_read);

            // Check if we've received all headers
            if (request.find("\r\n\r\n") != std::string::npos) {
                // Check for Content-Length
                std::regex cl_regex("Content-Length:\\s*(\\d+)");
                std::smatch match;
                if (std::regex_search(request, match, cl_regex)) {
                    size_t content_length = std::stoull(match[1]);
                    size_t body_start = request.find("\r\n\r\n") + 4;
                    size_t body_received = request.length() - body_start;

                    // Read remaining body if needed
                    while (body_received < content_length) {
                        bytes_read = recv(client, buffer, BUFFER_SIZE - 1, 0);
                        if (bytes_read > 0) {
                            buffer[bytes_read] = '\0';
                            request.append(buffer, bytes_read);
                            body_received += bytes_read;
                        }
                        else {
                            break;
                        }
                    }
                }
                break;
            }
        }
        else if (bytes_read == 0) {
            break; // Connection closed
        }
        else {
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK && error != 0) {
                break;
            }
        }
    } while (bytes_read > 0);

    return request;
}

// File information structure
struct FileInfo {
    std::string name;
    unsigned long long size;
    time_t mod_time;

    FileInfo() : size(0), mod_time(0) {}
    FileInfo(const std::string& n, unsigned long long s, time_t t)
        : name(n), size(s), mod_time(t) {
    }
};

// Serve FREE PUBLIC page
void serve_public_page(SOCKET client) {
    // Calculate public upload directory size
    unsigned long long total_size = 0;
    int file_count = 0;
    std::vector<FileInfo> files;

    try {
        for (auto& entry : fs::directory_iterator(UPLOAD_DIR)) {
            if (fs::is_regular_file(entry.path())) {
                try {
                    auto file_size = static_cast<unsigned long long>(fs::file_size(entry.path()));
                    total_size += file_size;
                    file_count++;

                    std::string filename = entry.path().filename().string();
                    if (filename[0] == '.') continue;

                    auto mod_time = fs::last_write_time(entry.path());
                    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                        mod_time - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
                    time_t mod_time_t = std::chrono::system_clock::to_time_t(sctp);

                    files.emplace_back(filename, file_size, mod_time_t);
                }
                catch (...) {}
            }
        }
    }
    catch (...) {
        // Directory might not exist yet
    }

    double total_gb = total_size / (1024.0 * 1024.0 * 1024.0);
    double percent_used = (total_size * 100.0) / static_cast<double>(FREE_MAX_TOTAL_UPLOADS);
    if (percent_used > 100.0) percent_used = 100.0;

    std::ostringstream html;
    html << "<!DOCTYPE html><html><head>"
        << "<title>MiniCloud - Free File Sharing</title>"
        << "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        << "<style>"
        << "body { font-family: 'Segoe UI', Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; min-height: 100vh; }"
        << ".container { background: rgba(255,255,255,0.1); backdrop-filter: blur(10px); padding: 30px; border-radius: 15px; margin: 20px 0; }"
        << "h1 { text-align: center; margin-bottom: 30px; }"
        << ".stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }"
        << ".stat-card { background: rgba(255,255,255,0.2); padding: 20px; border-radius: 10px; text-align: center; }"
        << ".stat-value { font-size: 2em; font-weight: bold; }"
        << ".upload-box { background: white; color: #333; padding: 25px; border-radius: 10px; margin: 30px 0; }"
        << "input[type='file'] { width: 100%; padding: 15px; border: 2px dashed #667eea; border-radius: 8px; margin: 10px 0; }"
        << "button { padding: 12px 30px; background: #667eea; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; margin: 10px 5px; }"
        << "button:hover { background: #5a67d8; }"
        << ".file-item { background: rgba(255,255,255,0.3); padding: 15px; margin: 10px 0; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; }"
        << "</style>"
        << "<script>"
        << "function checkFileSize() {"
        << "  const files = document.getElementById('fileInput').files;"
        << "  const maxSize = " << FREE_MAX_FILE_SIZE << ";"
        << "  for(let i = 0; i < files.length; i++) {"
        << "    if(files[i].size > maxSize) {"
        << "      alert('File \\\"' + files[i].name + '\\\" exceeds 100MB limit!');"
        << "      return false;"
        << "    }"
        << "  }"
        << "  return true;"
        << "}"
        << "</script>"
        << "</head><body>"
        << "<div class='container'>"
        << "<h1>MiniCloud Free File Sharing</h1>"
        << "<div class='stats'>"
        << "<div class='stat-card'><div class='stat-value'>" << file_count << "</div><div>Files Stored</div></div>"
        << "<div class='stat-card'><div class='stat-value'>" << std::fixed << std::setprecision(2) << total_gb << " GB</div><div>Storage Used</div></div>"
        << "</div>"
        << "<div class='upload-box'>"
        << "<h3>Upload Files (Max 100MB each)</h3>"
        << "<form method='POST' action='/upload' enctype='multipart/form-data' onsubmit='return checkFileSize()'>"
        << "<input type='file' name='file' id='fileInput' required>"
        << "<button type='submit'>Upload File</button>"
        << "</form>"
        << "</div>"
        << "<div style='text-align: center; margin: 20px 0;'>"
        << "<a href='/login'><button style='background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);'>Login for Premium (2GB files)</button></a>"
        << "</div>";

    // List public files
    html << "<div style='background: rgba(255,255,255,0.2); padding: 20px; border-radius: 10px; margin-top: 20px;'>"
        << "<h3>Available Files</h3>";

    if (file_count == 0) {
        html << "<p style='text-align: center;'>No files uploaded yet</p>";
    }
    else {
        for (const auto& file_info : files) {
            double size_mb = file_info.size / (1024.0 * 1024.0);
            std::string size_str;
            if (size_mb < 1) {
                size_str = std::to_string(static_cast<int>(file_info.size / 1024.0)) + " KB";
            }
            else {
                std::ostringstream size_stream;
                size_stream << std::fixed << std::setprecision(size_mb < 10 ? 2 : 1) << size_mb << " MB";
                size_str = size_stream.str();
            }

            html << "<div class='file-item'>"
                << "<span>" << file_info.name << " (" << size_str << ")</span>"
                << "<a href='/uploads/" << file_info.name << "' download><button>Download</button></a>"
                << "</div>";
        }
    }

    html << "</div></div></body></html>";

    send_response(client, html.str());
}

// Serve login page
void serve_login(SOCKET client, const std::string& error = "") {
    std::ostringstream html;
    html << "<!DOCTYPE html><html><head>"
        << "<title>Login - MiniCloud</title>"
        << "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        << "<style>"
        << "body { font-family: 'Segoe UI', Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; padding: 20px; }"
        << ".login-box { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); width: 100%; max-width: 400px; }"
        << "h1 { text-align: center; color: #333; margin-bottom: 30px; }"
        << "input { width: 100%; padding: 15px; margin: 10px 0; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; box-sizing: border-box; }"
        << "input:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2); }"
        << "button { width: 100%; padding: 15px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; margin-top: 10px; font-weight: bold; }"
        << ".error { background: #fee; color: #c33; padding: 12px; border-radius: 8px; margin-bottom: 20px; text-align: center; }"
        << ".info { text-align: center; margin-top: 25px; color: #666; font-size: 14px; padding: 15px; background: #f8f9fa; border-radius: 8px; }"
        << "</style>"
        << "</head><body>"
        << "<div class='login-box'>"
        << "<h1>Admin Login</h1>";

    if (!error.empty()) {
        html << "<div class='error'>" << error << "</div>";
    }

    html << "<form method='POST' action='/login'>"
        << "<input type='text' name='username' placeholder='Username' required>"
        << "<input type='password' name='password' placeholder='Password' required>"
        << "<button type='submit'>Login</button>"
        << "</form>"
        << "<div class='info'>"
        << "<strong>Default credentials:</strong><br>"
        << "Username: admin<br>"
        << "Password: Not telling you!"
        << "</div>"
        << "<div style='text-align: center; margin-top: 20px;'>"
        << "<a href='/' style='color: #667eea; text-decoration: none;'>Back to Free Version</a>"
        << "</div>"
        << "</div>"
        << "</body></html>";

    send_response(client, html.str());
}

// Handle login
void handle_login(SOCKET client, const std::string& request) {
    std::regex username_regex("username=([^&]+)");
    std::regex password_regex("password=([^&]+)");
    std::smatch user_match, pass_match;

    std::string username, password;

    if (std::regex_search(request, user_match, username_regex)) {
        username = user_match[1].str();
    }
    if (std::regex_search(request, pass_match, password_regex)) {
        password = pass_match[1].str();
    }

    // Decode URL encoding (simple version)
    std::replace(username.begin(), username.end(), '+', ' ');
    std::replace(password.begin(), password.end(), '+', ' ');

    // Check credentials
    if (username == "admin" && password == "12345678") {
        std::string session_id = generate_session_id();
        time_t now = time(nullptr);
        Session session(session_id, now, now, "admin", true);

        {
            std::lock_guard<std::mutex> lock(session_mutex);
            active_sessions[session_id] = session;
        }

        std::string cookie = "session=" + session_id + "; HttpOnly; Max-Age=3600";
        send_redirect(client, "/admin", cookie);
        safe_log("Admin logged in: " + username);
    }
    else {
        serve_login(client, "Invalid username or password");
    }
}

// Serve ADMIN page
void serve_admin_page(SOCKET client, const Session& session) {
    // Calculate statistics
    unsigned long long total_size = 0;
    int file_count = 0;
    std::vector<FileInfo> files;

    try {
        for (auto& entry : fs::directory_iterator(UPLOAD_DIR)) {
            if (fs::is_regular_file(entry.path())) {
                try {
                    auto file_size = static_cast<unsigned long long>(fs::file_size(entry.path()));
                    total_size += file_size;
                    file_count++;

                    std::string filename = entry.path().filename().string();
                    if (filename[0] == '.') continue;

                    auto mod_time = fs::last_write_time(entry.path());
                    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                        mod_time - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
                    time_t mod_time_t = std::chrono::system_clock::to_time_t(sctp);

                    files.emplace_back(filename, file_size, mod_time_t);
                }
                catch (...) {}
            }
        }
    }
    catch (...) {
        // Directory might not exist
    }

    double total_gb = total_size / (1024.0 * 1024.0 * 1024.0);

    std::ostringstream html;
    html << "<!DOCTYPE html><html><head>"
        << "<title>MiniCloud - Admin</title>"
        << "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        << "<style>"
        << "body { font-family: 'Segoe UI', Arial; max-width: 1000px; margin: 0 auto; padding: 20px; background: #0f172a; color: #f8fafc; }"
        << ".header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; padding: 25px; background: linear-gradient(135deg, #1e293b 0%, #334155 100%); border-radius: 15px; }"
        << ".admin-badge { background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); color: white; padding: 8px 16px; border-radius: 20px; font-weight: bold; }"
        << ".stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }"
        << ".stat-card { background: #1e293b; padding: 25px; border-radius: 12px; border-left: 5px solid #3b82f6; }"
        << ".stat-value { font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }"
        << ".upload-box { background: #1e293b; padding: 30px; border-radius: 12px; margin: 30px 0; border: 2px dashed #3b82f6; }"
        << "input[type='file'] { width: 100%; padding: 20px; background: #0f172a; color: white; border: 2px solid #334155; border-radius: 8px; margin: 15px 0; font-size: 16px; }"
        << "button { padding: 12px 24px; background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: bold; margin: 10px 5px; }"
        << ".logout-btn { background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%); }"
        << ".danger-btn { background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); }"
        << ".file-table { width: 100%; background: #1e293b; border-radius: 12px; overflow: hidden; margin: 30px 0; }"
        << ".file-table th { background: #334155; padding: 15px; text-align: left; }"
        << ".file-table td { padding: 12px 15px; border-bottom: 1px solid #334155; }"
        << ".action-btn { padding: 8px 16px; background: #475569; color: white; border: none; border-radius: 6px; cursor: pointer; margin: 0 5px; }"
        << ".delete-btn { background: #7f1d1d; }"
        << "</style>"
        << "<script>"
        << "function checkAdminFileSize() {"
        << "  const files = document.getElementById('fileInput').files;"
        << "  const maxSize = " << ADMIN_MAX_FILE_SIZE << ";"
        << "  for(let i = 0; i < files.length; i++) {"
        << "    if(files[i].size > maxSize) {"
        << "      alert('File \\\"' + files[i].name + '\\\" exceeds 3GB limit!');"
        << "      return false;"
        << "    }"
        << "  }"
        << "  return true;"
        << "}"
        << "function deleteFile(filename) {"
        << "  if(confirm('Delete \"' + filename + '\"?')) {"
        << "    window.location.href = '/delete?file=' + filename;"
        << "  }"
        << "}"
        << "</script>"
        << "</head><body>"
        << "<div class='header'>"
        << "<h1 style='margin: 0;'>MiniCloud Admin Dashboard</h1>"
        << "<div style='display: flex; gap: 15px; align-items: center;'>"
        << "<span class='admin-badge'>ADMIN MODE</span>"
        << "<a href='/logout'><button class='logout-btn'>Logout</button></a>"
        << "</div>"
        << "</div>"
        << "<div class='stats-grid'>"
        << "<div class='stat-card'>"
        << "<div class='stat-value'>" << file_count << "</div>"
        << "<div>Total Files</div>"
        << "</div>"
        << "<div class='stat-card'>"
        << "<div class='stat-value'>" << std::fixed << std::setprecision(2) << total_gb << " GB</div>"
        << "<div>Storage Used</div>"
        << "</div>"
        << "<div class='stat-card'>"
        << "<div class='stat-value'>3 GB</div>"
        << "<div>Max File Size</div>"
        << "</div>"
        << "</div>"
        << "<div class='upload-box'>"
        << "<h2>Upload Files (Premium - 3GB max)</h2>"
        << "<form method='POST' action='/upload' enctype='multipart/form-data' onsubmit='return checkAdminFileSize()'>"
        << "<input type='file' name='file' id='fileInput' required>"
        << "<button type='submit'>Upload File</button>"
        << "</form>"
        << "</div>"
        << "<div style='text-align: center; margin: 20px 0;'>"
        << "<button onclick='if(confirm(\"Delete ALL files?\")) window.location.href=\"/clear\"' class='danger-btn'>Clear All Files</button>"
        << "<a href='/'><button>View Public Site</button></a>"
        << "</div>";

    if (file_count > 0) {
        html << "<h2>Managed Files</h2>"
            << "<table class='file-table'>"
            << "<thead><tr><th>Filename</th><th>Size</th><th>Actions</th></tr></thead>"
            << "<tbody>";

        for (const auto& file_info : files) {
            double size_mb = file_info.size / (1024.0 * 1024.0);
            std::string size_str;
            if (size_mb < 1) {
                size_str = std::to_string(static_cast<int>(file_info.size / 1024.0)) + " KB";
            }
            else {
                std::ostringstream size_stream;
                size_stream << std::fixed << std::setprecision(size_mb < 10 ? 2 : 1) << size_mb << " MB";
                size_str = size_stream.str();
            }

            html << "<tr>"
                << "<td>" << file_info.name << "</td>"
                << "<td>" << size_str << "</td>"
                << "<td>"
                << "<a href='/uploads/" << file_info.name << "' download><button class='action-btn'>Download</button></a>"
                << "<button class='action-btn delete-btn' onclick='deleteFile(\"" << file_info.name << "\")'>Delete</button>"
                << "</td>"
                << "</tr>";
        }

        html << "</tbody></table>";
    }

    html << "</body></html>";

    send_response(client, html.str());
}

// Handle file upload
void handle_upload(SOCKET client, const std::string& request, const Session& session) {
    bool is_admin = session.is_admin;
    unsigned long long max_file_size = is_admin ? ADMIN_MAX_FILE_SIZE : FREE_MAX_FILE_SIZE;

    // Extract boundary
    std::regex boundary_regex("boundary=(.*)");
    std::smatch match;
    if (!std::regex_search(request, match, boundary_regex)) {
        send_error(client, 400, "Bad Request");
        return;
    }

    std::string boundary = "--" + match[1].str();
    size_t body_start = request.find("\r\n\r\n");

    if (body_start == std::string::npos) {
        send_error(client, 400, "Bad Request");
        return;
    }

    body_start += 4; // Skip the \r\n\r\n

    // Find the file data between boundaries
    size_t first_boundary = request.find(boundary);
    if (first_boundary == std::string::npos) {
        send_error(client, 400, "Bad Request");
        return;
    }

    size_t second_boundary = request.find(boundary, first_boundary + boundary.length());
    if (second_boundary == std::string::npos) {
        send_error(client, 400, "Bad Request");
        return;
    }

    // Extract filename
    std::regex filename_regex("filename=\"([^\"]+)\"");
    std::smatch fname_match;
    std::string headers = request.substr(first_boundary, second_boundary - first_boundary);

    if (!std::regex_search(headers, fname_match, filename_regex)) {
        send_error(client, 400, "No file uploaded");
        return;
    }

    std::string filename = fname_match[1].str();
    if (filename.empty() || filename == "null") {
        send_error(client, 400, "Invalid filename");
        return;
    }

    // Find the actual file data (after \r\n\r\n in the part)
    size_t part_body_start = headers.find("\r\n\r\n");
    if (part_body_start == std::string::npos) {
        send_error(client, 400, "Bad Request");
        return;
    }

    part_body_start += 4;
    std::string file_data = headers.substr(part_body_start);

    // Remove trailing \r\n before the next boundary
    if (file_data.size() >= 2 && file_data.substr(file_data.size() - 2) == "\r\n") {
        file_data.resize(file_data.size() - 2);
    }

    // Check file size
    if (file_data.size() > max_file_size) {
        std::string limit_str = is_admin ? "3GB" : "100MB";
        send_response(client, "File too large (max " + limit_str + ")", "text/plain");
        return;
    }

    // Sanitize filename
    std::string safe_filename;
    for (char c : filename) {
        if (c == '\\' || c == '/' || c == ':' || c == '*' || c == '?' ||
            c == '\"' || c == '<' || c == '>' || c == '|') {
            safe_filename += '_';
        }
        else {
            safe_filename += c;
        }
    }

    // Handle duplicate filenames
    std::string final_filename = safe_filename;
    int counter = 1;
    while (fs::exists(UPLOAD_DIR + "/" + final_filename)) {
        size_t dot_pos = safe_filename.find_last_of('.');
        if (dot_pos != std::string::npos) {
            final_filename = safe_filename.substr(0, dot_pos) +
                "_" + std::to_string(counter) +
                safe_filename.substr(dot_pos);
        }
        else {
            final_filename = safe_filename + "_" + std::to_string(counter);
        }
        counter++;
    }

    // Save file
    std::ofstream out(UPLOAD_DIR + "/" + final_filename, std::ios::binary);
    if (!out) {
        send_error(client, 500, "Internal Server Error");
        return;
    }

    out.write(file_data.data(), static_cast<std::streamsize>(file_data.size()));
    out.close();

    if (!out) {
        send_error(client, 500, "Internal Server Error");
        return;
    }

    total_uploads++;
    total_bandwidth += file_data.size();
    safe_log((is_admin ? "[ADMIN] " : "[FREE] ") + std::string("Uploaded: ") +
        final_filename + " (" + std::to_string(file_data.size() / 1024) + " KB)");

    send_redirect(client, is_admin ? "/admin" : "/");
}

// File download handler
void send_file(SOCKET client, const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file) {
        send_error(client, 404, "Not Found");
        return;
    }

    std::streamsize file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::string filename = fs::path(filepath).filename().string();
    std::string mime_type = get_mime_type(filename);

    std::string header = "HTTP/1.1 200 OK\r\n";
    header += "Content-Type: " + mime_type + "\r\n";
    header += "Content-Length: " + std::to_string(file_size) + "\r\n";
    header += "Content-Disposition: attachment; filename=\"" + filename + "\"\r\n";
    header += "Connection: close\r\n\r\n";

    if (!send_all(client, header.c_str(), static_cast<int>(header.size()))) {
        closesocket(client);
        return;
    }

    char buffer[BUFFER_SIZE];
    long long total_sent = 0;

    while (file.read(buffer, BUFFER_SIZE) || file.gcount() > 0) {
        int bytes_to_send = static_cast<int>(file.gcount());
        int sent = send(client, buffer, bytes_to_send, 0);
        if (sent <= 0) break;
        total_sent += sent;
        total_bandwidth += sent;
    }

    total_downloads++;
    safe_log("Downloaded: " + filename + " (" + std::to_string(total_sent) + " bytes)");
    file.close();
}

// Handle file deletion
void handle_delete(SOCKET client, const std::string& request, const Session& session) {
    if (!session.is_admin) {
        send_redirect(client, "/");
        return;
    }

    std::regex file_regex("GET /delete\\?file=([^ ]+)");
    std::smatch match;

    if (std::regex_search(request, match, file_regex)) {
        std::string filename = match[1].str();

        // Security check
        if (filename.find("..") != std::string::npos ||
            filename.find("/") != std::string::npos ||
            filename.find("\\") != std::string::npos) {
            send_response(client, "Invalid filename", "text/plain");
            return;
        }

        fs::path file_path = UPLOAD_DIR + "/" + filename;
        if (fs::exists(file_path)) {
            try {
                auto file_size = fs::file_size(file_path);
                fs::remove(file_path);
                safe_log("[ADMIN] Deleted: " + filename + " (" + std::to_string(file_size / 1024) + " KB)");
            }
            catch (...) {
                safe_log("[ADMIN] Failed to delete: " + filename);
            }
        }
    }

    send_redirect(client, "/admin");
}

// Clear uploads
void clear_uploads(const Session& session) {
    if (!session.is_admin) return;

    int count = 0;
    for (auto& entry : fs::directory_iterator(UPLOAD_DIR)) {
        if (fs::is_regular_file(entry.path())) {
            try {
                fs::remove(entry.path());
                count++;
            }
            catch (...) {}
        }
    }
    safe_log("[ADMIN] Cleared " + std::to_string(count) + " files");
}

// Clean old sessions
void cleanup_sessions() {
    while (server_running) {
        Sleep(60000); // Check every minute

        std::lock_guard<std::mutex> lock(session_mutex);
        time_t now = time(nullptr);
        auto it = active_sessions.begin();
        while (it != active_sessions.end()) {
            if (difftime(now, it->second.last_activity) > 3600) { // 1 hour timeout
                it = active_sessions.erase(it);
            }
            else {
                ++it;
            }
        }
    }
}

// Monitor thread for keyboard input
void monitor_thread() {
    while (server_running) {
        if (_kbhit()) {
            int key = _getch();

            if (key == '1' && !monitor_mode) {
                monitor_mode = true;
                system("cls");

                while (monitor_mode && server_running) {
                    monitor.display_monitor();

                    // Show current status
                    ServerStats stats = monitor.get_stats();
                    std::cout << "\nCurrent Status:\n";
                    std::cout << "  Active Connections: " << stats.connections << "\n";
                    std::cout << "  Total Uploads: " << stats.uploads << "\n";
                    std::cout << "  Total Downloads: " << stats.downloads << "\n";

                    double bandwidth_mb = stats.bandwidth / (1024.0 * 1024.0);
                    std::cout << "  Total Bandwidth: " << std::fixed << std::setprecision(2)
                        << bandwidth_mb << " MB\n";

                    int days = static_cast<int>(stats.uptime / 86400);
                    int hours = static_cast<int>((stats.uptime % 86400) / 3600);
                    int minutes = static_cast<int>((stats.uptime % 3600) / 60);
                    std::cout << "  Uptime: " << days << "d " << hours << "h " << minutes << "m\n";

                    std::cout << "\nEnter command or press [2] to exit: ";

                    if (_kbhit()) {
                        int cmd = _getch();

                        switch (cmd) {
                        case '2':
                            monitor_mode = false;
                            system("cls");
                            break;
                        case '3':
                            monitor.show_detailed_stats();
                            break;
                        case '4':
                            system("cls");
                            break;
                        case '5':
                            monitor.show_active_sessions();
                            break;
                        case '6':
                            monitor.show_upload_directory();
                            break;
                        case '7':
                            monitor.show_recent_logs();
                            break;
                        case '8':
                            monitor.reset_statistics();
                            break;
                        case '9':
                            monitor.show_help();
                            break;
                        case '0':
                            monitor_mode = false;
                            system("cls");
                            break;
                        default:
                            // Check for string commands
                            std::string command;
                            std::cout << "\n> ";
                            std::getline(std::cin, command);

                            if (command == "exit" || command == "2") {
                                monitor_mode = false;
                                system("cls");
                            }
                            else if (command == "stats" || command == "3") {
                                monitor.show_detailed_stats();
                            }
                            else if (command == "sessions" || command == "5") {
                                monitor.show_active_sessions();
                            }
                            else if (command == "logs" || command == "7") {
                                monitor.show_recent_logs();
                            }
                            else if (command == "clear" || command == "4") {
                                system("cls");
                            }
                            else if (command == "help" || command == "9") {
                                monitor.show_help();
                            }
                            else if (command == "reset" || command == "8") {
                                monitor.reset_statistics();
                            }
                            else if (!command.empty()) {
                                std::cout << "Unknown command. Type 'help' for available commands.\n";
                                std::cout << "Press any key to continue...";
                                _getch();
                            }
                            break;
                        }
                    }

                    // Small delay to prevent high CPU usage
                    Sleep(100);
                }
            }
            else if (key == 3) { // Ctrl+C
                server_running = false;
                safe_log("Server shutting down...");
                break;
            }
        }
        Sleep(100); // Check for keyboard input every 100ms
    }
}

// Main function
int main() {
    // Create directories
    fs::create_directory(UPLOAD_DIR);
    fs::create_directory(SESSION_DIR);

    // Start session cleanup thread
    std::thread(cleanup_sessions).detach();

    // Start monitor thread
    std::thread(monitor_thread).detach();

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Winsock initialization failed\n";
        return 1;
    }

    // Create socket
    SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server == INVALID_SOCKET) {
        std::cerr << "Socket creation failed\n";
        WSACleanup();
        return 1;
    }

    // Set socket options
    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    // Bind socket
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed. Port " << PORT << " may be in use.\n";
        std::cerr << "Try changing PORT constant to 8081 or 8888\n";
        closesocket(server);
        WSACleanup();
        return 1;
    }

    // Listen
    if (listen(server, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed\n";
        closesocket(server);
        WSACleanup();
        return 1;
    }

    // Print startup info
    std::cout << "==============================================================\n";
    std::cout << "                 MINICLOUD SERVER                      \n";
    std::cout << "==============================================================\n";
    std::cout << " Server running on: http://localhost:" << PORT << "\n";
    std::cout << " Upload directory: " << UPLOAD_DIR << "\n";
    std::cout << " Free tier: 100MB max file size, 1GB total storage\n";
    std::cout << " Admin tier: 3GB max file size, 10GB total storage\n";
    std::cout << " Admin login: http://localhost:" << PORT << "/login\n";
    std::cout << " Default credentials: admin / 12345678\n";
    std::cout << "==============================================================\n";
    std::cout << " Press [1] to enter Monitor Mode\n";
    std::cout << " Press Ctrl+C to stop the server\n";
    std::cout << "==============================================================\n\n";

    safe_log("Server started successfully");

    // Main server loop
    fd_set readfds;
    timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    while (server_running) {
        FD_ZERO(&readfds);
        FD_SET(server, &readfds);

        int activity = select(0, &readfds, nullptr, nullptr, &timeout);

        if (activity == SOCKET_ERROR) {
            if (server_running) {
                safe_log("Select error: " + std::to_string(WSAGetLastError()));
            }
            continue;
        }

        if (activity > 0 && FD_ISSET(server, &readfds)) {
            SOCKET client = accept(server, nullptr, nullptr);
            if (client == INVALID_SOCKET) {
                Sleep(10);
                continue;
            }

            active_connections++;

            // Set timeout
            int timeout_val = 30000; // 30 seconds
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_val, sizeof(timeout_val));
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout_val, sizeof(timeout_val));

            // Read request
            std::string request = read_complete_request(client);

            if (request.empty()) {
                closesocket(client);
                active_connections--;
                continue;
            }

            // Check authentication
            Session session;
            bool is_authenticated = check_authentication(request, session);

            // Route requests
            if (request.find("GET / ") == 0 || request.find("GET /index.html") == 0) {
                serve_public_page(client);
            }
            else if (request.find("GET /login") == 0) {
                serve_login(client);
            }
            else if (request.find("POST /login") == 0) {
                handle_login(client, request);
            }
            else if (request.find("GET /logout") == 0) {
                send_redirect(client, "/", "session=; Max-Age=0");
            }
            else if (request.find("GET /admin") == 0) {
                if (is_authenticated && session.is_admin) {
                    serve_admin_page(client, session);
                }
                else {
                    send_redirect(client, "/login");
                }
            }
            else if (request.find("GET /uploads/") == 0) {
                size_t pos = request.find(" ");
                size_t pos2 = request.find(" ", pos + 1);
                std::string path = "." + request.substr(pos + 1, pos2 - pos - 1);

                if (path.find("..") != std::string::npos) {
                    send_error(client, 403, "Forbidden");
                }
                else {
                    send_file(client, path);
                }
            }
            else if (request.find("POST /upload") == 0) {
                handle_upload(client, request, session);
            }
            else if (request.find("GET /clear") == 0) {
                if (is_authenticated && session.is_admin) {
                    clear_uploads(session);
                    send_redirect(client, "/admin");
                }
                else {
                    send_redirect(client, "/");
                }
            }
            else if (request.find("GET /delete") == 0) {
                handle_delete(client, request, session);
            }
            else {
                send_error(client, 404, "Not Found Fuh");
            }

            // Add a small delay to ensure data is sent
            Sleep(10);
            closesocket(client);
            active_connections--;
        }

        // Small sleep to prevent CPU spinning
        Sleep(10);
    }

    // Cleanup
    safe_log("Server stopping...");
    closesocket(server);
    WSACleanup();

    // Wait a bit for threads to finish
    Sleep(1000);

    std::cout << "\nServer stopped. Press any key to exit...";
    _getch();

    return 0;
}