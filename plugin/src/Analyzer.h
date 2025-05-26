#pragma once

#include <zeek/analyzer/protocol/tcp/TCP.h>

using namespace zeek;

namespace zeek::plugin::mms {
   
    class Analyzer : public zeek::analyzer::Analyzer {
        public:
            explicit Analyzer(const char *name, Connection* conn);
            void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen);
    };

} // namespace zeek::analyzer::mms
