@load base/protocols/conn/removal-hooks

module mms;

# =====================================================================
# Attach requests in order to be able to evaluate them in the context
# of the response.
# =====================================================================
redef record connection += {
    mms_read_requests: table[int] of ReadRequest &default=table();
    mms_write_requests: table[int] of WriteRequest &default=table();
    mms_name_list_requests: table[int] of GetNameListRequest &default=table();
    mms_get_variable_access_attributes_request: table[int] of GetVariableAccessAttributesRequest &default=table();
    mms_defineNamedVariableListRequest: table[int] of DefineNamedVariableListRequest &default=table();
};

# =====================================================================
# The following events are called when a corresponding PDU is received.
# =====================================================================
global initiateRequestPdu: event(c: connection, pdu: InitiateRequestPdu);
global initiateResponsePdu: event(c: connection, pdu: InitiateResponsePdu);
global initiateErrorPdu: event(c: connection, pdu: InitiateErrorPdu);
global readRequest: event(c: connection, invokeID: int, pdu: ReadRequest);
global writeRequest: event(c: connection, invokeID: int, pdu: WriteRequest);
global getNameListRequest: event(c: connection, invokeID: int, pdu: GetNameListRequest);
global getVariableAccessAttributesRequest: event(c: connection, invokeID: int, pdu: GetVariableAccessAttributesRequest);
global defineNamedVariableListRequest: event(c: connection, invokeID: int, pdu: DefineNamedVariableListRequest);
global getNamedVariableListAttributesRequest: event(c: connection, invokeID: int, pdu: GetNamedVariableListAttributesRequest);
global deleteNamedVariableListRequest: event(c: connection, invokeID: int, pdu: DeleteNamedVariableListRequest);
global readResponse: event(c: connection, invokeID: int, pdu: ReadResponse);
global writeResponse: event(c: connection, invokeID: int, pdu: WriteResponse);
global getNameListResponse: event(c: connection, invokeID: int, pdu: GetNameListResponse);
global getVariableAccessAttributesResponse: event(c: connection, invokeID: int, pdu: GetVariableAccessAttributesResponse);
global defineNamedVariableListResponse: event(c: connection, invokeID: int, pdu: DefineNamedVariableListResponse);
global getNamedVariableListAttributesResponse: event(c: connection, invokeID: int, pdu: GetNamedVariableListAttributesResponse);
global deleteNamedVariableListResponse: event(c: connection, invokeID: int, pdu: DeleteNamedVariableListResponse);
global informationReport_evt: event(c: connection, pdu: InformationReport);

# =====================================================================
# The following events are called when a variable (or variable list) is
# read, written or reported. Several such events can arise from one PDU
# =====================================================================
global VariableReadRequest: event(c: connection, name: ObjectName);
global VariableListReadRequest: event(c: connection, listname: ObjectName);
global VariableReadResponse: event(c: connection, name: ObjectName, data: Data);
global VariableReadResponseError: event(c: connection, name: ObjectName, error: DataAccessError);
global VariableListReadResponse: event(c: connection, listname: ObjectName, data: Data);
global VariableListReadResponseError: event(c: connection, listname: ObjectName, error: DataAccessError);

global VariableWriteRequest: event(c: connection, name: ObjectName, data: Data);
global VariableListWriteRequest: event(c: connection, listname: ObjectName, data: Data);
global VariableWriteResponse: event(c: connection, name: ObjectName, data: Data);
global VariableWriteResponseError: event(c: connection, name: ObjectName, data: Data, error: DataAccessError);
global VariableListWriteResponse: event(c: connection, listname: ObjectName, data: Data);
global VariableListWriteResponseError: event(c: connection, listname: ObjectName, data: Data, error: DataAccessError);

global VariableReport: event(c: connection, name: ObjectName, data: Data);
global VariableReportError: event(c: connection, name: ObjectName, error: DataAccessError);
global VariableListReport: event(c: connection, listname: ObjectName, data: Data);
global VariableListReportError: event(c: connection, listname: ObjectName, error: DataAccessError);

global NameList: event(c: connection, request: GetNameListRequest, response: GetNameListResponse);
global VariableAccessAttributes: event(c: connection, request: GetVariableAccessAttributesRequest, response: GetVariableAccessAttributesResponse);
global NamedVariableListAttributes: event(c: connection, request: DefineNamedVariableListRequest, response: GetNamedVariableListAttributesResponse);


# =====================================================================
# Mapping of a general MmsPdu to the respective PDU type it contains
# =====================================================================
event mms::mms_pdu(c: connection, is_orig: bool, pdu: MmsPdu) {
    if(pdu ?$ initiateRequestPdu) {
        event initiateRequestPdu(
            c,
            pdu $ initiateRequestPdu
        );
    } else if(pdu ?$ initiateResponsePdu) {
        event initiateResponsePdu(
            c,
            pdu $ initiateResponsePdu
        );
    } else if(pdu ?$ initiateErrorPdu) {
        event initiateErrorPdu(
            c,
            pdu $ initiateErrorPdu
        );
    } else if(pdu ?$ confirmedRequestPdu) {
        if(pdu $ confirmedRequestPdu $ confirmedServiceRequest ?$ read) {
            event readRequest(
                c,
                pdu $ confirmedRequestPdu $ invokeID,
                pdu $ confirmedRequestPdu $ confirmedServiceRequest $ read
            );
        } else if(pdu $ confirmedRequestPdu $ confirmedServiceRequest ?$ write) {
            event writeRequest(
                c,
                pdu $ confirmedRequestPdu $ invokeID,
                pdu $ confirmedRequestPdu $ confirmedServiceRequest $ write
            );
        } else if(pdu $ confirmedRequestPdu $ confirmedServiceRequest ?$ getNameList) {
            event getNameListRequest(
                c,
                pdu $ confirmedRequestPdu $ invokeID,
                pdu $ confirmedRequestPdu $ confirmedServiceRequest $ getNameList
            );
        } else if(pdu $ confirmedRequestPdu $ confirmedServiceRequest ?$ getVariableAccessAttributes) {
            event getVariableAccessAttributesRequest(
                c,
                pdu $ confirmedRequestPdu $ invokeID,
                pdu $ confirmedRequestPdu $ confirmedServiceRequest $ getVariableAccessAttributes
            );
        } else if(pdu $ confirmedRequestPdu $ confirmedServiceRequest ?$ defineNamedVariableList) {
            event defineNamedVariableListRequest(
                c,
                pdu $ confirmedRequestPdu $ invokeID,
                pdu $ confirmedRequestPdu $ confirmedServiceRequest $ defineNamedVariableList
            );
        } else if(pdu $ confirmedRequestPdu $ confirmedServiceRequest ?$ getNamedVariableListAttributes) {
            event getNamedVariableListAttributesRequest(
                c,
                pdu $ confirmedRequestPdu $ invokeID,
                pdu $ confirmedRequestPdu $ confirmedServiceRequest $ getNamedVariableListAttributes
            );
        } else if(pdu $ confirmedRequestPdu $ confirmedServiceRequest ?$ deleteNamedVariableList) {
            event deleteNamedVariableListRequest(
                c,
                pdu $ confirmedRequestPdu $ invokeID,
                pdu $ confirmedRequestPdu $ confirmedServiceRequest $ deleteNamedVariableList
            );
        }
    } else if(pdu ?$ confirmedResponsePdu) {
        if(pdu $ confirmedResponsePdu $ confirmedServiceResponse ?$ read) {
            event readResponse(
                c,
                pdu $ confirmedResponsePdu $ invokeID,
                pdu $ confirmedResponsePdu $ confirmedServiceResponse $ read
            );
        } else if(pdu $ confirmedResponsePdu $ confirmedServiceResponse ?$ write) {
            event writeResponse(
                c,
                pdu $ confirmedResponsePdu $ invokeID,
                pdu $ confirmedResponsePdu $ confirmedServiceResponse $ write
            );
        } else if(pdu $ confirmedResponsePdu $ confirmedServiceResponse ?$ getNameList) {
            event getNameListResponse(
                c,
                pdu $ confirmedResponsePdu $ invokeID,
                pdu $ confirmedResponsePdu $ confirmedServiceResponse $ getNameList
            );
        } else if(pdu $ confirmedResponsePdu $ confirmedServiceResponse ?$ getVariableAccessAttributes) {
            event getVariableAccessAttributesResponse(
                c,
                pdu $ confirmedResponsePdu $ invokeID,
                pdu $ confirmedResponsePdu $ confirmedServiceResponse $ getVariableAccessAttributes
            );
        } else if(pdu $ confirmedResponsePdu $ confirmedServiceResponse ?$ defineNamedVariableList) {
            event defineNamedVariableListResponse(
                c,
                pdu $ confirmedResponsePdu $ invokeID,
                pdu $ confirmedResponsePdu $ confirmedServiceResponse $ defineNamedVariableList
            );
        } else if(pdu $ confirmedResponsePdu $ confirmedServiceResponse ?$ getNamedVariableListAttributes) {
            event getNamedVariableListAttributesResponse(
                c,
                pdu $ confirmedResponsePdu $ invokeID,
                pdu $ confirmedResponsePdu $ confirmedServiceResponse $ getNamedVariableListAttributes
            );
        } else if(pdu $ confirmedResponsePdu $ confirmedServiceResponse ?$ deleteNamedVariableList) {
            event deleteNamedVariableListResponse(
                c,
                pdu $ confirmedResponsePdu $ invokeID,
                pdu $ confirmedResponsePdu $ confirmedServiceResponse $ deleteNamedVariableList
            );
        }
    } else if(pdu ?$ unconfirmedPDU) {
        event informationReport_evt(
            c,
            pdu $ unconfirmedPDU $ unconfirmedService $ informationReport
        );
    }

}

# =====================================================================
# Mapping a ReadRequest pdu to (possible multiple) VariableReadRequest
# or VariableListReadRequest events
# =====================================================================
event readRequest(c: connection, invokeID: int, pdu: ReadRequest) {
    # if specificationWithResult is false then the result will omit the variableAccessSpecification.
    # In that case we have to reconstruct them later 
    if (! pdu $ specificationWithResult) {
        c $ mms_read_requests[invokeID] = pdu;
    }
    if (pdu $ variableAccessSpecification ?$ listOfVariable) {
        for (i in pdu $ variableAccessSpecification $ listOfVariable) {
            event VariableReadRequest(c, pdu $ variableAccessSpecification $ listOfVariable[i] $ variableSpecification $ name);
        }
    }
    if (pdu $ variableAccessSpecification ?$ variableListName) {
        event VariableListReadRequest(c, pdu $ variableAccessSpecification $ variableListName);
    }
}

# =====================================================================
# Mapping a ReadResponse pdu to (possible multiple) VariableReadResponse
# VariableReadResponseError, VariableListReadResponse or
# VariableListReadResponseError
# =====================================================================
event readResponse(c: connection, invokeID: int, pdu: ReadResponse) {
    # if the variableAccessSpecification is stored in our connection 
    # we are using it
    local name: ObjectName;
    local vas = invokeID in c $ mms_read_requests
       ? c $ mms_read_requests[invokeID] $ variableAccessSpecification
       : pdu $ variableAccessSpecification;
    for (i in pdu $ listOfAccessResult) {
        if(vas ?$ listOfVariable) {
            name = vas $ listOfVariable[i] $ variableSpecification $ name;
            if ( pdu $ listOfAccessResult[i] ?$ success) {
                 event VariableReadResponse(c, name, pdu $ listOfAccessResult[i] $ success);
            } else {
                 event VariableReadResponseError(c, name, pdu $ listOfAccessResult[i] $ failure);
            }
        } else {
            name = vas $ variableListName;
            if ( pdu $ listOfAccessResult[i] ?$ success) {
                 event VariableListReadResponse(c, name, pdu $ listOfAccessResult[i] $ success);
            } else {
                 event VariableListReadResponseError(c, name, pdu $ listOfAccessResult[i] $ failure);
            }
        }
    }
}
 
# =====================================================================
# Mapping a WriteRequest pdu to (possible multiple) VariableWriteRequest
# or VariableListWriteRequest events
# =====================================================================
event writeRequest(c: connection, invokeID: int, pdu: WriteRequest) {
    c $ mms_write_requests[invokeID] = pdu;
    for (i in pdu $ variableAccessSpecification $ listOfVariable) {
        event VariableWriteRequest(
            c,
            pdu $ variableAccessSpecification $ listOfVariable[i] $ variableSpecification $ name,
            pdu $ listOfData[i]
        );
    }
    if (pdu $ variableAccessSpecification ?$ variableListName) {
        event VariableListWriteRequest(
            c,
            pdu $ variableAccessSpecification $ variableListName,
            pdu $ listOfData[0]
        );
    }
}

event writeResponse(c: connection, invokeID: int, pdu: WriteResponse) {
    if(! (invokeID in c $ mms_write_requests))
        return;
    local request = c $ mms_write_requests[invokeID];
    local name: ObjectName;
    for(i in pdu) {
        if(request $ variableAccessSpecification ?$ listOfVariable) {
            name = request $ variableAccessSpecification $ listOfVariable[i] $ variableSpecification $ name;
            if(pdu[i] ?$ success) {
                event VariableWriteResponse(c, name, request $ listOfData[i]);
            } else {
                event VariableWriteResponseError(c, name, request $ listOfData[i], pdu[i] $ failure);
            }
        } else {
            name = request $ variableAccessSpecification $ variableListName;
            if(pdu[i] ?$ success) {
                event VariableListWriteResponse(c, name, request $ listOfData[i]);
            } else {
                event VariableListWriteResponseError(c, name, request $ listOfData[i], pdu[i] $ failure);
            }
        }
    }
}

event informationReport_evt(c: connection, pdu: InformationReport) {
    local name: ObjectName;
    for(i in pdu $ listOfAccessResult) {
        if(pdu $ variableAccessSpecification ?$ listOfVariable) {
            name = pdu $ variableAccessSpecification $ listOfVariable[i] $ variableSpecification $ name;
            if(pdu $ listOfAccessResult[i] ?$ success) {
                event VariableReport(c, name, pdu $ listOfAccessResult[i] $ success);
            } else {
                event VariableReportError(c, name, pdu $ listOfAccessResult[i] $ failure);
            }
        } else {
            name = pdu $ variableAccessSpecification $ variableListName;
            if(pdu $ listOfAccessResult[i] ?$ success) {
                event VariableListReport(c, name, pdu $ listOfAccessResult[i] $ success);
            } else {
                event VariableListReportError(c, name, pdu $ listOfAccessResult[i] $ failure);
            }
        }
    }
}

event getNameListRequest(c: connection, invokeID: int, pdu: GetNameListRequest) {
    c $ mms_name_list_requests[invokeID] = pdu;
}

event getNameListResponse(c: connection, invokeID: int, pdu: GetNameListResponse) {
    if(invokeID in c $ mms_name_list_requests)
        event NameList(c, c $ mms_name_list_requests[invokeID], pdu);
}

event getVariableAccessAttributesRequest(c: connection, invokeID: int, pdu: GetVariableAccessAttributesRequest) {
    c $ mms_get_variable_access_attributes_request[invokeID] = pdu;
}

event getVariableAccessAttributesResponse(c: connection, invokeID: int, pdu: GetVariableAccessAttributesResponse) {
    if(invokeID in c $ mms_get_variable_access_attributes_request)
        event VariableAccessAttributes(c, c $ mms_get_variable_access_attributes_request[invokeID], pdu);
}

event defineNamedVariableListRequest(c: connection, invokeID: int, pdu: DefineNamedVariableListRequest) {
    c $ mms_defineNamedVariableListRequest[invokeID] = pdu;
}

event getNamedVariableListAttributesResponse(c: connection, invokeID: int, pdu: GetNamedVariableListAttributesResponse) {
    if(invokeID in c $ mms_defineNamedVariableListRequest)
        event NamedVariableListAttributes(c, c $ mms_defineNamedVariableListRequest[invokeID], pdu);
}
