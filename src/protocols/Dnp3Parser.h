#ifndef DNP3_PARSER_H
#define DNP3_PARSER_H

#include "BaseProtocolParser.h"

class Dnp3Parser : public BaseProtocolParser {
public:
    ~Dnp3Parser() override = default;
    
    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;
};

#endif
