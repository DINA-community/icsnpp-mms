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
    local val: string="";
    local val_t: string="";

    if(data?$array) {
        val+="[";
        for(i in data$array) {
            if(i!=0)
                val+=",";
            val+=data_to_string(data $ array[i]);
        }
        val+="]";
        val_t = "array";
    } else if (data?$structure) {
        val+="[";
        for(i in data $ structure) {
            if(i!=0)
                val+=",";
            val+=data_to_string(data$structure[i]);
        }
        val+="]";
        val_t = "structure";
    } else if(data?$boolean) {
        val = to_json(fmt("%s", data$boolean));
        val_t = "boolean";
    } else if(data?$bit_string) {
        val = to_json("0x" + string_to_ascii_hex(data$bit_string));
        val_t = "bit_string";
    } else if(data?$integer) {
        val = to_json(fmt("%d", data$integer));
        val_t = "integer";
    } else if(data?$unsigned) {
        val = to_json(fmt("%d", data$unsigned));
        val_t = "unsigned";
    } else if(data?$floating_point) {
        val = to_json("0x" + string_to_ascii_hex(data$floating_point));
        val_t = "floating_point";
    } else if(data?$octet_string) {
        val = to_json("0x" + string_to_ascii_hex(data$octet_string));
        val_t = "octet_string";
    } else if(data?$visible_string) {
        val = to_json(data$visible_string);
        val_t = "visible_string";
    } else if(data?$binary_time) {
        val = to_json("0x" + string_to_ascii_hex(data$binary_time));
        val_t = "binary_time";
    } else if(data?$mMSString) {
        val = to_json(data$mMSString);
        val_t = "mms_string";
    } else if(data?$utc_time) {
        val = to_json("0x" + string_to_ascii_hex(data$utc_time));
        val_t = "utc_time";
    } else {
        val = to_json("<unknown>");
        val_t = "bit_string";
    }

    return "{\"type\": \""+val_t+"\", \"value\": "+val+"}";
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

function typeSpecification_to_string(ts: TypeSpecification, fieldName: string &default=""): string {

    local val_f: string="";
    local val_t: string="";
    local val_n: string=fieldName;

    if(ts ?$ array) {
        val_t = "array";
        val_f += typeSpecification_to_string(ts$array$elementType);
    } else if(ts ?$ structure) {
        val_t = "structure";
        for(i in ts$structure$components) {
            local comp = ts$structure$components[i];
            if(i!=0)
                val_f+=",";
            val_f += typeSpecification_to_string(comp$componentType, comp$componentName);
        }
    } else if(ts ?$ boolean) {
        val_t = "bool";
    } else if(ts ?$ bit_string) {
        val_t = "bitString";
    } else if(ts ?$ integer) {
        val_t = "integer";
    } else if(ts ?$ unsigned) {
        val_t = "unsigned";
    } else if(ts ?$ octet_string) {
        val_t = "octetString";
    } else if(ts ?$ visible_string) {
        val_t = "visibleString";
    } else {
        val_t = "<unknown>";
    }

    return "{\"name\": \""+val_n+"\", \"type\": \""+val_t+"\", \"fields\": ["+val_f+"]}";
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