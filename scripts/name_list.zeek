module mms;

@load ./helper

export {

    redef enum Log::ID += { LOG_NAMELIST };

    type NameListRecord: record {
        ts:         time     &log;
        uid:        string   &log;
        id:         conn_id  &log;
        class:      string   &log &optional;
        scope:      string   &log &optional;
        domain:      string   &log &optional;
        value:      string   &log &optional;
        success:    bool     &log;
        diag:       string   &log &optional;
    };

    global log_mms_name_list: event(rec: NameListRecord);

    const log_name_list: bool = T &redef;
}

event zeek_init() &priority=5
{
    Log::create_stream(mms::LOG_NAMELIST, [$columns = NameListRecord, $ev = log_mms_name_list, $path="mms_name_list"]);
}

event NameList(c: connection, request: GetNameList_Request, response: GetNameList_Response) {
    local scope: string;
    local value: string;
    local class: string;
    local domain: string;

    if(!log_name_list) return;

    class = remove_ns(cat(request $ extendedObjectClass $ objectClass));

    if(request $ objectScope ?$ vmdSpecific) {
        scope="vmdSpecific";
    } else if(request $ objectScope ?$ aaSpecific) {
        scope="aaSpecific";
    } else {
        scope="domainSpecific";
        domain=request $ objectScope $ domainSpecific;
    }

    for(i in response $ listOfIdentifier) {
        if(i!=0)
            value+=",";
        value+=response $ listOfIdentifier[i];
    }

    local rec: NameListRecord = record(
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $success=T
    );

    if(|class| > 0) {
        rec$class = class;
    }

    if(|scope| > 0) {
        rec$scope = scope;
    }

    if(|domain| > 0) {
        rec$domain = domain;
    }

    if(|value| > 0) {
        rec$value = value;
    }

    Log::write(LOG_NAMELIST, rec);
}

event NameListError (c: connection, request: GetNameList_Request, response: Confirmed_ErrorPDU) {
    local scope: string;
    local class: string;
    local domain: string;

    if(!log_var_attributes) return;

    class = remove_ns(cat(request $ extendedObjectClass $ objectClass));

    if(request $ objectScope ?$ vmdSpecific) {
        scope="vmdSpecific";
    } else if(request $ objectScope ?$ aaSpecific) {
        scope="aaSpecific";
    } else {
        scope="domainSpecific";
        domain=request $ objectScope $ domainSpecific;
    }

    local rec: NameListRecord = record(
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $success=F,
        $diag=errorClass_to_string(response$serviceError)
    );

    if(|class| > 0) {
        rec$class = class;
    }

    if(|scope| > 0) {
        rec$scope = scope;
    }

    if(|domain| > 0) {
        rec$domain = domain;
    }

    Log::write(LOG_NAMELIST, rec);
}

