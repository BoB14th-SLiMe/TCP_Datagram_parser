#ifndef MODBUS_PARSER_H
#define MODBUS_PARSER_H

#include "BaseProtocolParser.h"
#include <map>

struct ModbusRequestInfo {
    uint8_t function_code = 0;
    uint16_t start_address = 0;
};

class ModbusParser : public BaseProtocolParser {
public:
    ~ModbusParser() override = default;

    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;

private:
    std::map<std::string, std::map<uint16_t, ModbusRequestInfo>> m_pending_requests;
};

#endif