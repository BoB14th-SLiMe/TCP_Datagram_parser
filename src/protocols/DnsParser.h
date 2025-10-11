#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include "BaseProtocolParser.h"

class DnsParser : public BaseProtocolParser {
public:
    ~DnsParser() override;
    
    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;
};

#endif

