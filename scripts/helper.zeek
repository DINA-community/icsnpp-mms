module mms;

function remove_ns(val: string): string {
    local parts = split_string(val, /::/);
    local len = |parts|;
    if(len < 2)
        return val;
    return parts[len - 1];
}

function nice_ParameterCBB(vec: ParameterSupportOptions): string {
    local str = "";
    for(i in vec) {
        str += remove_ns(cat(vec[i]));
        if(i < |vec|-1) str += ",";
    }
    return clean(str);
}

function nice_servicesSupported(vec: ServiceSupportOptions): string {
    local str = "";
    for(i in vec) {
        str += remove_ns(cat(vec[i]));
        if(i < |vec|-1) str += ",";
    }
    return clean(str);
}

function data_to_string(data: Data): string {
    local res: string="";
    if(data ?$ array) {
        for(i in data $ array) {
            if(i!=0)
                res+=",";
            res+=data_to_string(data $ array[i]);
        }
        return res;
    } else if (data ?$ structure) {
        for(i in data $ structure) {
            if(i!=0)
                res+=",";
            res+=data_to_string(data $ structure[i]);
        }
        return res;
    } else if(data?$boolean) {
        return fmt("%s", data$boolean);
    } else if(data?$bit_string) {
        return "0x" + string_to_ascii_hex(data$bit_string);
    } else if(data?$integer) {
        return fmt("%d", data$integer);
    } else if(data?$unsigned) {
        return fmt("%d", data$unsigned);
    } else if(data?$floating_point) {
        return "0x" + string_to_ascii_hex(data$floating_point);
    } else if(data?$octet_string) {
        return "0x" + string_to_ascii_hex(data$octet_string);
    } else if(data?$visible_string) {
        return data$visible_string;
    } else if(data?$binary_time) {
        return "0x" + string_to_ascii_hex(data$binary_time);
    } else if(data?$mMSString) {
        return data$mMSString;
    } else if(data?$utc_time) {
        return "0x" + string_to_ascii_hex(data$utc_time);
    } else {
        return "<unknown>";
    }
}

function data_to_type(data: Data): string {
    if(data ?$ array) {
       return "array";
    } else if (data ?$ structure) {
       return "structure";
    } else if(data ?$ boolean) {
        return "boolean";
    } else if(data ?$ bit_string) {
        return "bit_string";
    } else if(data ?$ integer) {
        return "integer";
    } else if(data ?$ unsigned) {
        return "unsigned";
    } else if(data ?$ floating_point) {
        return "float";
    } else if(data ?$ octet_string) {
        return "octet";
    } else if(data ?$ visible_string) {
        return "string";
    } else if(data ?$ binary_time) {
        return "btime";
    } else if(data ?$ mMSString) {
        return "string";
    } else if(data ?$ utc_time) {
        return "time";
    } else {
        return "<unknown>";
    }
}

function objectName_to_string(name: ObjectName): string {
    if(name ?$ vmd_specific) {
        return name $ vmd_specific;
    } else if (name ?$ aa_specific) {
        return name $ aa_specific + " (aa)";
    } else if (name ?$ domain_specific) {
        return  name $ domain_specific $ domainId + "::" + name $ domain_specific $ itemId;
    } else {
        return "<unknown>";
    }
}


function typeSpecification_to_string(ts: TypeSpecification): string {
    local res="";
    if(ts ?$ array) {
        return "array";
    } else if(ts ?$ structure) {
        for(i in ts $ structure $ components) {
            local comp = ts $ structure $ components[i];
            if(i!=0)
                res+=",";
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
        return "<unknown>";
    }
}


function errorClass_to_string(err: ServiceError): string {
    local cls = err$errorClass;
    local str = "";

    if(cls?$vmd_state) {
        str = cat(cls$vmd_state);
    } else if (cls?$application_reference) {
        str = cat(cls$access);
    } else if (cls?$definition) {
        str = cat(cls$definition);
    } else if (cls?$resource) {
        str = cat(cls$resource);
    } else if (cls?$service) {
        str = cat(cls$service);
    } else if (cls?$service_preempt) {
        str = cat(cls$service_preempt);
    } else if (cls?$time_resolution) {
        str = cat(cls$time_resolution);
    } else if (cls?$access) {
        str = cat(cls$access);
    } else if (cls?$initiate) {
        str = cat(cls$initiate);
    } else if (cls?$conclude) {
        str = cat(cls$conclude);
    } else if (cls?$_cancel) {
        str = cat(cls$_cancel);
    } else if (cls?$_file) {
        str = cat(cls$_file);
    } else if (cls?$others) {
        str = cat(cls$others);
    } else {
        str = "<unknown>";
    }

    return remove_ns(str);
}