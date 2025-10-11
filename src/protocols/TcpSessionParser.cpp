#include "TcpSessionParser.h"

TcpSessionParser::TcpSessionParser() {}
TcpSessionParser::~TcpSessionParser() {}

std::string TcpSessionParser::getName() const {
    return "tcp_session";
}

// Generates and returns only the content for the "d" field in the JSON
std::string TcpSessionParser::parse(uint32_t seq, uint32_t ack, uint8_t flags) const {
    std::stringstream details_ss;
    // The sq, ak, fl info already exists at the top level,
    // so we can leave the 'd' field empty or add extra info.
    // For consistency, we'll leave it empty here.
    details_ss << "{}";
    return details_ss.str();
}
