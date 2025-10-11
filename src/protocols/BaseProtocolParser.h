#ifndef BASE_PROTOCOL_PARSER_H
#define BASE_PROTOCOL_PARSER_H

#include "IProtocolParser.h"

class BaseProtocolParser : public IProtocolParser {
public:
    ~BaseProtocolParser() override = default;
    void setOutputStream(std::ofstream* json_stream, std::ofstream* csv_stream) override;

protected:
    void writeOutput(const PacketInfo& info, const std::string& details_json);

    std::ofstream* m_json_stream = nullptr;
    std::ofstream* m_csv_stream = nullptr;

private:
    std::string escape_csv(const std::string& s);
};

#endif

