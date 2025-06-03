#include "Analyzer.h"
#include "Plugin.h"
#include "process.h"
#include "events.bif.h"

#include <zeek/analyzer/Manager.h>

using namespace zeek;

namespace zeek::plugin::mms {

Analyzer::Analyzer(const char* name, zeek::Connection* c) : zeek::analyzer::Analyzer(name, c) {}

void Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t, const IP_Hdr*, int) {
    MmsPdu *pdu_raw = NULL;
    auto desc = &asn_DEF_MmsPdu;

    asn_dec_rval_t rval = ber_decode(nullptr, desc, reinterpret_cast<void**>(&pdu_raw), data, len);
    if(rval.code != RC_OK) {
        Weird("mms_parse_error", "unable to parse packet");
        return;
    }
    // For debugging purposes
    //asn_fprint(stdout, desc, pdu_raw);

    char errbuf[128];
    size_t errlen = sizeof(errbuf)/sizeof(errbuf[0]);
    if(asn_check_constraints(desc, pdu_raw, errbuf, &errlen)) {
        Weird("mms_constraint_error", errbuf);
        desc->free_struct(desc, pdu_raw, 0);
        return;
    }

    auto pdu=process_MmsPdu(pdu_raw);
    desc->free_struct(desc, pdu_raw, 0);
    
    zeek::BifEvent::mms::enqueue_mms_pdu(this, Conn(), orig, pdu);
}

} // namespace zeek::plugin::mms
