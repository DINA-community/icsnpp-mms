@load base/protocols/conn/removal-hooks

module mms;

# =====================================================================
# Attach requests in order to be able to evaluate them in the context
# of the response.
# =====================================================================
redef record connection += {
    mms_read_requests: table[int] of Read_Request &default=table();
    mms_write_requests: table[int] of Write_Request &default=table();
    mms_name_list_requests: table[int] of GetNameList_Request &default=table();
    mms_get_variable_access_attributes_request: table[int] of GetVariableAccessAttributes_Request &default=table();
    mms_defineNamedVariableListRequest: table[int] of DefineNamedVariableList_Request &default=table();
};

export {

    # =====================================================================
    # The following events are called when a corresponding PDU is received.
    # =====================================================================
    global initiateRequestPdu: event(c: connection, pdu: Initiate_RequestPDU);
    global initiateResponsePdu: event(c: connection, pdu: Initiate_ResponsePDU);
    global initiateErrorPdu: event(c: connection, pdu: Initiate_ErrorPDU);
    global readRequest: event(c: connection, invokeID: int, pdu: Read_Request);
    global writeRequest: event(c: connection, invokeID: int, pdu: Write_Request);
    global getNameListRequest: event(c: connection, invokeID: int, pdu: GetNameList_Request);
    global getVariableAccessAttributesRequest: event(c: connection, invokeID: int, pdu: GetVariableAccessAttributes_Request);
    global defineNamedVariableListRequest: event(c: connection, invokeID: int, pdu: DefineNamedVariableList_Request);
    global getNamedVariableListAttributesRequest: event(c: connection, invokeID: int, pdu: GetNamedVariableListAttributes_Request);
    global deleteNamedVariableListRequest: event(c: connection, invokeID: int, pdu: DeleteNamedVariableList_Request);
    global readResponse: event(c: connection, invokeID: int, pdu: Read_Response);
    global writeResponse: event(c: connection, invokeID: int, pdu: Write_Response);
    global getNameListResponse: event(c: connection, invokeID: int, pdu: GetNameList_Response);
    global getVariableAccessAttributesResponse: event(c: connection, invokeID: int, pdu: GetVariableAccessAttributes_Response);
    global defineNamedVariableListResponse: event(c: connection, invokeID: int, pdu: DefineNamedVariableList_Response);
    global getNamedVariableListAttributesResponse: event(c: connection, invokeID: int, pdu: GetNamedVariableListAttributes_Response);
    global deleteNamedVariableListResponse: event(c: connection, invokeID: int, pdu: DeleteNamedVariableList_Response);
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

    global NameList: event(c: connection, request: GetNameList_Request, response: GetNameList_Response);
    global VariableAccessAttributes: event(c: connection, request: GetVariableAccessAttributes_Request, response: GetVariableAccessAttributes_Response);
    global NamedVariableListAttributes: event(c: connection, request: DefineNamedVariableList_Request, response: GetNamedVariableListAttributes_Response);

}

# =====================================================================
# Mapping of a general MMSpdu to the respective PDU type it contains
# =====================================================================
event mms::mms_pdu(c: connection, is_orig: bool, pdu: MMSpdu) {
    if(pdu ?$ initiate_RequestPDU) {
        event initiateRequestPdu(
            c,
            pdu $ initiate_RequestPDU
        );
    } else if(pdu ?$ initiate_ResponsePDU) {
        event initiateResponsePdu(
            c,
            pdu $ initiate_ResponsePDU
        );
    } else if(pdu ?$ initiate_ErrorPDU) {
        event initiateErrorPdu(
            c,
            pdu $ initiate_ErrorPDU
        );
    } else if(pdu ?$ confirmed_RequestPDU) {
        if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ read) {
            event readRequest(
                c,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ read
            );
        } else if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ write) {
            event writeRequest(
                c,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ write
            );
        } else if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ getNameList) {
            event getNameListRequest(
                c,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ getNameList
            );
        } else if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ getVariableAccessAttributes) {
            event getVariableAccessAttributesRequest(
                c,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ getVariableAccessAttributes
            );
        } else if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ defineNamedVariableList) {
            event defineNamedVariableListRequest(
                c,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ defineNamedVariableList
            );
        } else if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ getNamedVariableListAttributes) {
            event getNamedVariableListAttributesRequest(
                c,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ getNamedVariableListAttributes
            );
        } else if(pdu $ confirmed_RequestPDU $ confirmedServiceRequest ?$ deleteNamedVariableList) {
            event deleteNamedVariableListRequest(
                c,
                pdu $ confirmed_RequestPDU $ invokeID,
                pdu $ confirmed_RequestPDU $ confirmedServiceRequest $ deleteNamedVariableList
            );
        }
    } else if(pdu ?$ confirmed_ResponsePDU) {
        if(pdu $ confirmed_ResponsePDU $ confirmedServiceResponse ?$ read) {
            event readResponse(
                c,
                pdu $ confirmed_ResponsePDU $ invokeID,
                pdu $ confirmed_ResponsePDU $ confirmedServiceResponse $ read
            );
        } else if(pdu $ confirmed_ResponsePDU $ confirmedServiceResponse ?$ write) {
            event writeResponse(
                c,
                pdu $ confirmed_ResponsePDU $ invokeID,
                pdu $ confirmed_ResponsePDU $ confirmedServiceResponse $ write
            );
        } else if(pdu $ confirmed_ResponsePDU $ confirmedServiceResponse ?$ getNameList) {
            event getNameListResponse(
                c,
                pdu $ confirmed_ResponsePDU $ invokeID,
                pdu $ confirmed_ResponsePDU $ confirmedServiceResponse $ getNameList
            );
        } else if(pdu $ confirmed_ResponsePDU $ confirmedServiceResponse ?$ getVariableAccessAttributes) {
            event getVariableAccessAttributesResponse(
                c,
                pdu $ confirmed_ResponsePDU $ invokeID,
                pdu $ confirmed_ResponsePDU $ confirmedServiceResponse $ getVariableAccessAttributes
            );
        } else if(pdu $ confirmed_ResponsePDU $ confirmedServiceResponse ?$ defineNamedVariableList) {
            event defineNamedVariableListResponse(
                c,
                pdu $ confirmed_ResponsePDU $ invokeID,
                pdu $ confirmed_ResponsePDU $ confirmedServiceResponse $ defineNamedVariableList
            );
        } else if(pdu $ confirmed_ResponsePDU $ confirmedServiceResponse ?$ getNamedVariableListAttributes) {
            event getNamedVariableListAttributesResponse(
                c,
                pdu $ confirmed_ResponsePDU $ invokeID,
                pdu $ confirmed_ResponsePDU $ confirmedServiceResponse $ getNamedVariableListAttributes
            );
        } else if(pdu $ confirmed_ResponsePDU $ confirmedServiceResponse ?$ deleteNamedVariableList) {
            event deleteNamedVariableListResponse(
                c,
                pdu $ confirmed_ResponsePDU $ invokeID,
                pdu $ confirmed_ResponsePDU $ confirmedServiceResponse $ deleteNamedVariableList
            );
        }
    } else if(pdu ?$ unconfirmed_PDU) {
        event informationReport_evt(
            c,
            pdu $ unconfirmed_PDU $ unconfirmedService $ informationReport
        );
    }

}

# =====================================================================
# Mapping a Read_Request pdu to (possible multiple) VariableReadRequest
# or VariableListReadRequest events
# =====================================================================
event readRequest(c: connection, invokeID: int, pdu: Read_Request) {
    # if specificationWithResult is false then the result will omit the variableAccessSpecification.
    # In that case we have to reconstruct them later 
    if (! pdu $ specificationWithResult) {
        c $ mms_read_requests[invokeID] = pdu;
    }
    if (pdu $ variableAccessSpecificatn ?$ listOfVariable) {
        for (i in pdu $ variableAccessSpecificatn $ listOfVariable) {
            event VariableReadRequest(c, pdu $ variableAccessSpecificatn $ listOfVariable[i] $ variableSpecification $ name);
        }
    }
    if (pdu $ variableAccessSpecificatn ?$ variableListName) {
        event VariableListReadRequest(c, pdu $ variableAccessSpecificatn $ variableListName);
    }
}

# =====================================================================
# Mapping a Read_Response pdu to (possible multiple) VariableReadResponse
# VariableReadResponseError, VariableListReadResponse or
# VariableListReadResponseError
# =====================================================================
event readResponse(c: connection, invokeID: int, pdu: Read_Response) {
    # if the variableAccessSpecification is stored in our connection 
    # we are using it
    local name: ObjectName;
    local vas = invokeID in c $ mms_read_requests
       ? c $ mms_read_requests[invokeID] $ variableAccessSpecificatn
       : pdu $ variableAccessSpecificatn;
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
# Mapping a Write_Request pdu to (possible multiple) VariableWriteRequest
# or VariableListWriteRequest events
# =====================================================================
event writeRequest(c: connection, invokeID: int, pdu: Write_Request) {
    c $ mms_write_requests[invokeID] = pdu;
    for (i in pdu $ variableAccessSpecificatn $ listOfVariable) {
        event VariableWriteRequest(
            c,
            pdu $ variableAccessSpecificatn $ listOfVariable[i] $ variableSpecification $ name,
            pdu $ listOfData[i]
        );
    }
    if (pdu $ variableAccessSpecificatn ?$ variableListName) {
        event VariableListWriteRequest(
            c,
            pdu $ variableAccessSpecificatn $ variableListName,
            pdu $ listOfData[0]
        );
    }
}

event writeResponse(c: connection, invokeID: int, pdu: Write_Response) {
    if(! (invokeID in c $ mms_write_requests))
        return;
    local request = c $ mms_write_requests[invokeID];
    local name: ObjectName;
    for(i in pdu) {
        if(request $ variableAccessSpecificatn ?$ listOfVariable) {
            name = request $ variableAccessSpecificatn $ listOfVariable[i] $ variableSpecification $ name;
            if(pdu[i] ?$ success) {
                event VariableWriteResponse(c, name, request $ listOfData[i]);
            } else {
                event VariableWriteResponseError(c, name, request $ listOfData[i], pdu[i] $ failure);
            }
        } else {
            name = request $ variableAccessSpecificatn $ variableListName;
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

event getNameListRequest(c: connection, invokeID: int, pdu: GetNameList_Request) {
    c $ mms_name_list_requests[invokeID] = pdu;
}

event getNameListResponse(c: connection, invokeID: int, pdu: GetNameList_Response) {
    if(invokeID in c $ mms_name_list_requests)
        event NameList(c, c $ mms_name_list_requests[invokeID], pdu);
}

event getVariableAccessAttributesRequest(c: connection, invokeID: int, pdu: GetVariableAccessAttributes_Request) {
    c $ mms_get_variable_access_attributes_request[invokeID] = pdu;
}

event getVariableAccessAttributesResponse(c: connection, invokeID: int, pdu: GetVariableAccessAttributes_Response) {
    if(invokeID in c $ mms_get_variable_access_attributes_request)
        event VariableAccessAttributes(c, c $ mms_get_variable_access_attributes_request[invokeID], pdu);
}

event defineNamedVariableListRequest(c: connection, invokeID: int, pdu: DefineNamedVariableList_Request) {
    c $ mms_defineNamedVariableListRequest[invokeID] = pdu;
}

event getNamedVariableListAttributesResponse(c: connection, invokeID: int, pdu: GetNamedVariableListAttributes_Response) {
    if(invokeID in c $ mms_defineNamedVariableListRequest)
        event NamedVariableListAttributes(c, c $ mms_defineNamedVariableListRequest[invokeID], pdu);
}

