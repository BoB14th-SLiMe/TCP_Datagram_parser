#ifndef TCP_SESSION_PARSER_H
#define TCP_SESSION_PARSER_H

#include <string>
#include <sstream>
#include <cstdint>
#include <tuple>

class TcpSessionParser {
public:
    TcpSessionParser();
    ~TcpSessionParser();

    // Changed back to return a simple JSON string
    std::string parse(uint32_t seq, uint32_t ack, uint8_t flags) const;
    
    std::string getName() const;
};

#endif // TCP_SESSION_PARSER_H
