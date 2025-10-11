#ifndef XGT_FEN_PARSER_H
#define XGT_FEN_PARSER_H

#include "BaseProtocolParser.h"
#include <chrono>
#include <vector>
#include <map>
#include <string>

// Structure to store information about FEnet requests
struct XgtFenRequestInfo {
    uint16_t invoke_id = 0;
    uint16_t command = 0;
    uint16_t data_type = 0;
    std::chrono::steady_clock::time_point timestamp;
};

class XgtFenParser : public BaseProtocolParser {
public:
    ~XgtFenParser() override;

    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;

private:
    // Manages pending requests using Flow ID and Invoke ID as keys
    std::map<std::string, std::map<uint16_t, XgtFenRequestInfo>> m_pending_requests;
};

#endif // XGT_FEN_PARSER_H
