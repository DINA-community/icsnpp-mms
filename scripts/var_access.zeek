module mms;

redef enum Log::ID += { LOG };

type VariableAccess: record {
    ts:        time     &log &default=network_time();
    operation: string   &log;
    variable:  string   &log;
    value:     string   &log;
};

event zeek_init() &priority=5
{
    Log::create_stream(LOG, [
        $columns=VariableAccess, 
        $path="mms_var_access", 
    ]);
}

function objectName_to_string(name: ObjectName): string {
    if(name ?$ vmd_specific) {
        return name $ vmd_specific;
    } else if (name ?$ aa_specific) {
        return name $ aa_specific + " (aa)";
    } else if (name ?$ domain_specific) {
        return  name $ domain_specific $ domainId + "::" + name $ domain_specific $ itemId;
    } else {
        return "";
    }
}

function data_to_string(data: Data): string {
    local res: string="";
    if(data ?$ array) {
        for(i in data $ array) {
            if(i!=0)
                res+=", ";
            res+=data_to_string(data $ array[i]);
        }
        return res;
    } else if (data ?$ structure) {
        for(i in data $ structure) {
            if(i!=0)
                res+=", ";
            res+=data_to_string(data $ structure[i]);
        }
        return res;
    } else if(data ?$ boolean) {
        return cat(data $ boolean);
    } else if(data ?$ bit_string) {
        return cat(data $ bit_string);
    } else if(data ?$ integer) {
        return cat(data $ integer);
    } else if(data ?$ unsigned) {
        return cat(data $ unsigned);
    } else if(data ?$ floating_point) {
        return cat(data $ floating_point);
    } else if(data ?$ octet_string) {
        return cat(data $ octet_string);
    } else if(data ?$ visible_string) {
        return cat(data $ visible_string);
    } else if(data ?$ binary_time) {
        return cat(data $ binary_time);
    } else if(data ?$ mMSString) {
        return cat(data $ mMSString);
    } else if(data ?$ utc_time) {
        return cat(data $ utc_time);
    } else {    
        return "<UNKNOWN>";
    }
}

function getNameListRequest_to_string(request: GetNameList_Request): string {
    local scope: string;
    if(request $ objectScope ?$ vmdSpecific) {
        scope="vmdSpecific";
    } else if(request $ objectScope ?$ aaSpecific) {
        scope="aaSpecific";
    } else {
        scope="domain: "+request $ objectScope $ domainSpecific;
    }
    return "class: "+cat(request $ extendedObjectClass $ objectClass)+", scope: "+scope;
}

function typeSpecification_to_string(ts: TypeSpecification): string {
    local res="";
    if(ts ?$ array) {
        return "array";
    } else if(ts ?$ structure) {
        for(i in ts $ structure $ components) {
            local comp = ts $ structure $ components[i];
            if(i!=0)
                res+=", ";
            res += comp $ componentName;
            res += ": ";
            res += typeSpecification_to_string(comp $ componentType);
        }
        return "{"+res+"}";
    } else if(ts ?$ boolean) {
        return "bool";
    } else if(ts ?$ bit_string) {
        return "bitString";
    } else if(ts ?$ integer) {
        return "integer";
    } else if(ts ?$ unsigned) {
        return "unsigned";
    } else if(ts ?$ octet_string) {
        return "octetString";
    } else if(ts ?$ visible_string) {
        return "visibleString";
    } else {
        return "<UNKNOWN TYPE>";
    }
}

function log_access(operation: string, name: ObjectName, data: Data) {
    local rec=record(
        $operation=operation,
        $variable=objectName_to_string(name),
        $value=data_to_string(data)
    );
    Log::write(LOG, rec);
}

event VariableReadResponse(c: connection, name: ObjectName, data: Data) {
    log_access("read", name, data);
}

event VariableListReadResponse(c: connection, name: ObjectName, data: Data) {
    log_access("read-list", name, data);
}

event VariableWriteResponse(c: connection, name: ObjectName, data: Data) {
    log_access("write", name, data);
}

event VariableListWriteResponse(c: connection, name: ObjectName, data: Data) {
    log_access("write-list", name, data);
}

event VariableReport(c: connection, name: ObjectName, data: Data) {
    log_access("report", name, data);
}

event VariableListReport(c: connection, name: ObjectName, data: Data) {
    log_access("report-list", name, data);
}


event NameList(c: connection, request: GetNameList_Request, response: GetNameList_Response) {
    local res="";
    for(i in response $ listOfIdentifier) {
        if(i!=0)
            res+=", ";
        res+=response $ listOfIdentifier[i];
    }
    local rec=record(
        $operation="name-list",
        $variable=getNameListRequest_to_string(request),
        $value=res
    );
    Log::write(LOG, rec);
}


event VariableAccessAttributes(c: connection, request: GetVariableAccessAttributes_Request, response: GetVariableAccessAttributes_Response) {
    local rec=record(
        $operation="vaa",
        $variable=objectName_to_string(request $ name),
        $value=typeSpecification_to_string(response $ typeSpecification)
    );
    Log::write(LOG, rec);

}

event NamedVariableListAttributes(c: connection, request: DefineNamedVariableList_Request, response: GetNamedVariableListAttributes_Response) {
    local res="";
    for(i in response $ listOfVariable) {
        if(i!=0)
            res+=", ";
        res+=objectName_to_string(response $ listOfVariable[i] $ variableSpecification $ name);
    }
    local rec=record(
        $operation="vla",
        $variable=objectName_to_string(request $ variableListName),
        $value=res
    );
    Log::write(LOG, rec);
}
