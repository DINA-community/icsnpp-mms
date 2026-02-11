module mms;

@load ./helper

export {

    redef enum Log::ID += { LOG_VAR_ACCESS, LOG_VARLIST_ACCESS };

    type VariableAccess: record {
        ts:        time     &log;
        uid:       string   &log;
        id:        conn_id  &log;
        operation: string   &log;
        variable:  string   &log;
        value:     string   &log &optional;
        success:   bool     &log;
        diag:      string   &log &optional;
    };

    type VariableListAccess: record {
        ts:        time     &log;
        uid:       string   &log;
        id:        conn_id  &log;
        operation: string   &log;
        listname:  string   &log;
        listindex: count    &log;
        value:     string   &log &optional;
        success:   bool     &log;
        diag:      string   &log &optional;
    };

    global log_mms_var_access: event(rec: VariableAccess);
    global log_mms_varlist_access: event(rec: VariableListAccess);

    const log_var_access: bool = T &redef;
}

event zeek_init() &priority=5
{
    Log::create_stream(mms::LOG_VAR_ACCESS, [$columns = VariableAccess, $ev = log_mms_var_access, $path="mms_var_access"]);
    Log::create_stream(mms::LOG_VARLIST_ACCESS, [$columns = VariableListAccess, $ev = log_mms_varlist_access, $path="mms_varlist_access"]);
}

event VariableReadResponse(c: connection, name: ObjectName, data: Data) {

    if(!log_var_access) return;

    local rec: VariableAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="read",
        $variable=objectName_to_string(name),
        $value=data_to_string(data),
        $success=T
    ];

    Log::write(LOG_VAR_ACCESS, rec);
}

event VariableWriteResponse(c: connection, name: ObjectName, data: Data) {

    if(!log_var_access) return;

    local rec: VariableAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="write",
        $variable=objectName_to_string(name),
        $value=data_to_string(data),
        $success=T
    ];

    Log::write(LOG_VAR_ACCESS, rec);
}

event VariableReadResponseError(c: connection, name: ObjectName, error: DataAccessError) {

    if(!log_var_access) return;

    local rec: VariableAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="read",
        $variable=objectName_to_string(name),
        $success=F,
        $diag=remove_ns(cat(error))
    ];

    Log::write(LOG_VAR_ACCESS, rec);
}

event VariableWriteResponseError(c: connection, name: ObjectName, data: Data, error: DataAccessError) {

    if(!log_var_access) return;

    local rec: VariableAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="write",
        $variable=objectName_to_string(name),
        $value=data_to_string(data),
        $success=F,
        $diag=remove_ns(cat(error))
    ];

    Log::write(LOG_VAR_ACCESS, rec);
}


event VariableListReadResponse(c: connection, listname: ObjectName, listindex: count, data: Data) {

    if(!log_var_access) return;

    local rec: VariableListAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="read",
        $listname=objectName_to_string(listname),
        $listindex=listindex,
        $value=data_to_string(data),
        $success=T
    ];

    Log::write(LOG_VARLIST_ACCESS, rec);
}

event VariableListReadResponseError(c: connection, listname: ObjectName, listindex: count, error: DataAccessError) {

    if(!log_var_access) return;

    local rec: VariableListAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="read",
        $listname=objectName_to_string(listname),
        $listindex=listindex,
        $success=F,
        $diag=remove_ns(cat(error))
    ];

    Log::write(LOG_VARLIST_ACCESS, rec);
}

event VariableListWriteResponse(c: connection, listname: ObjectName, listindex: count, data: Data) {

    if(!log_var_access) return;

    local rec: VariableListAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="write",
        $listname=objectName_to_string(listname),
        $listindex=listindex,
        $value=data_to_string(data),
        $success=T
    ];

    Log::write(LOG_VARLIST_ACCESS, rec);
}

event VariableListWriteResponseError(c: connection, listname: ObjectName, listindex: count, data: Data, error: DataAccessError) {

    if(!log_var_access) return;

    local rec: VariableListAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="write",
        $listname=objectName_to_string(listname),
        $listindex=listindex,
        $value=data_to_string(data),
        $success=F,
        $diag=remove_ns(cat(error))
    ];

    Log::write(LOG_VARLIST_ACCESS, rec);
}


event VariableReport(c: connection, name: ObjectName, data: Data) {

    if(!log_var_access) return;

    local rec: VariableAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="report",
        $variable=objectName_to_string(name),
        $value=data_to_string(data),
        $success=T
    ];

    Log::write(LOG_VAR_ACCESS, rec);
}

event VariableReportError(c: connection, name: ObjectName, error: DataAccessError) {

    if(!log_var_access) return;

    local rec: VariableAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="report",
        $variable=objectName_to_string(name),
        $success=F,
        $diag=remove_ns(cat(error))
    ];

    Log::write(LOG_VAR_ACCESS, rec);
}

event VariableListReport(c: connection, listname: ObjectName, listindex: count, data: Data) {
    if(!log_var_access) return;

    local rec: VariableListAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="report",
        $listname=objectName_to_string(listname),
        $listindex=listindex,
        $value=data_to_string(data),
        $success=T
    ];

    Log::write(LOG_VARLIST_ACCESS, rec);
}

event VariableListReportError(c: connection, listname: ObjectName, listindex: count, error: DataAccessError) {
    if(!log_var_access) return;

    local rec: VariableListAccess = [
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $operation="report",
        $listname=objectName_to_string(listname),
        $listindex=listindex,
        $success=F,
        $diag=remove_ns(cat(error))
    ];

    Log::write(LOG_VARLIST_ACCESS, rec);
}