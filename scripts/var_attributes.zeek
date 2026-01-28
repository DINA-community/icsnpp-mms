module mms;

@load ./helper

export {

    redef enum Log::ID += { LOG_VAA };

    type VAA: record {
        ts:         time     &log;
        uid:        string   &log;
        id:         conn_id  &log;
        variable:   string   &log;
        attributes: string   &log &optional;
        success:    bool     &log;
        diag:       string   &log &optional;
    };

    global log_mms_var_attributes: event(rec: VAA);

    const log_var_attributes: bool = T &redef;
}

event zeek_init() &priority=5
{
    Log::create_stream(mms::LOG_VAA, [$columns = VAA, $ev = log_mms_var_attributes, $path="mms_var_attributes"]);
}

event VariableAccessAttributes(c: connection, request: GetVariableAccessAttributes_Request, response: GetVariableAccessAttributes_Response) {

    if(!log_var_attributes) return;

    local rec=record(
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $variable=objectName_to_string(request$name),
        $attributes=typeSpecification_to_string(response$typeSpecification),
        $success=T
    );

    Log::write(LOG_VAA, rec);
}

event VariableAccessAttributesError(c: connection, request: GetVariableAccessAttributes_Request, response: Confirmed_ErrorPDU) {

    if(!log_var_attributes) return;

    local rec=record(
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $variable=objectName_to_string(request$name),
        $success=F,
        $diag=errorClass_to_string(response$serviceError)
    );

    Log::write(LOG_VAA, rec);
}