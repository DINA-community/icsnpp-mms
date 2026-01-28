module mms;

@load ./helper

export {

    redef enum Log::ID += { LOG };

    type Info: record {
        ts:                   time    &log;
        uid:                  string  &log;
        id:                   conn_id &log;
        deviceVendor:         string &log &optional;
        deviceModel:          string &log &optional;
        deviceRevision:       string &log &optional;
        protocolVersion:      string &log  &optional;
        parameterCBB:         string &log &optional;
        servicesSupported:    string &log &optional;
    };

    redef record connection += {
        mms_info: Info &optional;
    };

    global log_mms: event(rec: Info);
}

function get_info(c: connection): Info {
    if(!c?$mms_info) {
        c$mms_info = [
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
        ];
    }
    return c$mms_info;
}

event zeek_init() &priority=5
{
    Log::create_stream(mms::LOG, [$columns = Info, $ev = log_mms, $path="mms"]);
}

event IdentifyResponse(c: connection, id: Identify_Response) {
    local info = get_info(c);

    if(id?$vendorName)
        info$deviceVendor = id$vendorName;
    if(id?$modelName)
        info$deviceModel = id$modelName;
    if(id?$revision)
        info$deviceRevision = id$revision;
}

event initiateRequestPdu(c: connection, pdu: Initiate_RequestPDU) {
}

event initiateResponsePdu(c: connection, pdu: Initiate_ResponsePDU) {
    local info = get_info(c);

    if(pdu?$mmsInitResponseDetail) {
        if(pdu$mmsInitResponseDetail?$negociatedParameterCBB)
            info$parameterCBB = nice_ParameterCBB(pdu$mmsInitResponseDetail$negociatedParameterCBB);
        if(pdu$mmsInitResponseDetail?$servicesSupportedCalled)
            info$servicesSupported = nice_servicesSupported(pdu$mmsInitResponseDetail$servicesSupportedCalled);
        if(pdu$mmsInitResponseDetail?$negociatedVersionNumber)
            info$protocolVersion = cat(pdu$mmsInitResponseDetail$negociatedVersionNumber);
    }
}

event connection_state_remove(c: connection) {
    if ( c?$mms_info ) {
        Log::write(LOG, c$mms_info);
        delete c$mms_info;
    }
}