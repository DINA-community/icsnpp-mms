module mms;

@load ./helper

export {

    redef enum Log::ID += { LOG_VARLIST_ATTR };

    type VarListAttributes: record {
        ts:         time     &log;
        uid:        string   &log;
        id:         conn_id  &log;
        list:       string   &log &optional;
        attributes: string   &log &optional;
        success:    bool     &log;
        diag:       string   &log &optional;
    };

    global log_mms_log_varlist_attributes: event(rec: VarListAttributes);

    const log_varlist_attributes: bool = T &redef;
}

event zeek_init() &priority=5
{
    Log::create_stream(mms::LOG_VARLIST_ATTR,
        [$columns = VarListAttributes,
        $ev = log_mms_log_varlist_attributes,
        $path="mms_varlist_attributes"]);
}

event NamedVariableListAttributes(c: connection, request: GetNamedVariableListAttributes_Request, response: GetNamedVariableListAttributes_Response) {

    if(!log_varlist_attributes) return;

    local list = objectName_to_string(request);
    local attributes = "";

    attributes += "[";
    for(i in response $ listOfVariable) {
        if(i!=0)
            attributes+=",";
        attributes+=to_json(objectName_to_string(response $ listOfVariable[i] $ variableSpecification $ name));
    }
    attributes += "]";

    local rec=record(
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $list=list,
        $attributes=attributes,
        $success=T
    );

    Log::write(LOG_VARLIST_ATTR, rec);
}

event NamedVariableListAttributesError (c: connection, request: GetNamedVariableListAttributes_Request, response: Confirmed_ErrorPDU) {

    if(!log_varlist_attributes) return;

    local list = objectName_to_string(request);
    local rec=record(
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $list=list,
        $success=F,
        $diag=errorClass_to_string(response$serviceError)
    );

    Log::write(LOG_VARLIST_ATTR, rec);
}