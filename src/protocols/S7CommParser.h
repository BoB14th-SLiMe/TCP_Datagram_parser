#ifndef S7COMM_PARSER_H
#define S7COMM_PARSER_H

#include "BaseProtocolParser.h"
#include <chrono>
#include <vector>
#include <map>

// S7comm item structure
struct S7CommItem {
    // Can be empty as we only need the item count for response parsing
};

// S7comm request info structure
struct S7CommRequestInfo {
    uint16_t pdu_ref = 0;
    uint8_t function_code = 0;
    std::vector<S7CommItem> items;
    std::chrono::steady_clock::time_point timestamp;
};

class S7CommParser : public BaseProtocolParser {
public:
    ~S7CommParser() override = default;

    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;

private:
    // Map of pending requests for the S7comm protocol
    std::map<std::string, std::map<uint16_t, S7CommRequestInfo>> m_pending_requests;
};

#endif // S7COMM_PARSER_H
