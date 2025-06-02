#THIS CODE IS GENERATED. DON'T CHANGE MANUALLY!
module mms;
export {
  
  # ======== PRIMITIVE TYPES =======
  type Unsigned32: int;
  
  type Identifier: string;
  
  type FloatingPoint: string;
  
  type TimeOfDay: string;
  
  type MMSString: string;
  
  type UtcTime: string;
  
  type DataAccessError: enum {
    objectInvalidated = 0,
    hardwareFault = 1,
    temporarilyUnavailable = 2,
    objectAccessDenied = 3,
    objectUndefined = 4,
    invalidAddress = 5,
    typeUnsupported = 6,
    typeInconsistent = 7,
    objectAttributeInconsistent = 8,
    objectAccessUnsupported = 9,
    objectNonExistent = 10,
    objectValueInvalid = 11,
  };
  
  type Integer32: int;
  
  type Unsigned8: int;
  
  type DefineNamedVariableListResponse: bool;
  
  type Integer16: int;
  
  type Integer8: int;
  
  type Unsigned16: int;
  
  
  # ======== FORWARD DECLARATIONS =======
  type AlternateAccess: record {};
  type AlternateAccessSelection: record {};
  type Data: record {};
  type TypeSpecification: record {};
  type StructComponent: record {};
  
  # ======== COMPLEX TYPES =======
  type ObjectClass: record {
    basicObjectClass: enum {
      namedVariable = 0,
      scatteredAccess = 1,
      namedVariableList = 2,
      namedType = 3,
      semaphore = 4,
      eventCondition = 5,
      eventAction = 6,
      eventEnrollment = 7,
      journal = 8,
      ObjectClass__domain = 9,
      programInvocation = 10,
      operatorStation = 11,
      dataExchange = 12,
      accessControlList = 13,
    } &optional;
  };
  
  type GetNameListRequest: record {
    objectClass: ObjectClass;
    objectScope: record {
      vmdSpecific: bool &optional;
      domainSpecific: Identifier &optional;
      aaSpecific: bool &optional;
    };
    continueAfter: Identifier &optional;
  };
  
  type ObjectName: record {
    vmdSpecific: Identifier &optional;
    domainSpecific: record {
      domainId: Identifier;
      itemId: Identifier;
    } &optional;
    aaSpecific: Identifier &optional;
  };
  
  type VariableSpecification: record {
    name: ObjectName &optional;
  };
  
  type IndexRangeSeq: record {
    lowIndex: Unsigned32;
    numberOfElements: Unsigned32;
  };
  
  type VariableDef: record {
    variableSpecification: VariableSpecification;
    alternateAccess: AlternateAccess &optional;
  };
  
  type VariableAccessSpecification: record {
    listOfVariable: vector of VariableDef &optional;
    variableListName: ObjectName &optional;
  };
  
  type ReadRequest: record {
    specificationWithResult: bool;
    variableAccessSpecification: VariableAccessSpecification;
  };
  
  type DataSequence: vector of Data;
  
  type WriteRequest: record {
    variableAccessSpecification: VariableAccessSpecification;
    listOfData: vector of Data;
  };
  
  type GetVariableAccessAttributesRequest: record {
    name: ObjectName &optional;
  };
  
  type DefineNamedVariableListRequest: record {
    variableListName: ObjectName;
    listOfVariable: vector of VariableDef;
  };
  
  type GetNamedVariableListAttributesRequest: ObjectName;
  
  type DeleteNamedVariableListRequest: record {
    scopeOfDelete: enum {
      specific = 0,
      aa_specific = 1,
      DeleteNamedVariableListRequest__domain = 2,
      vmd = 3,
    };
    listOfVariableListName: vector of ObjectName &optional;
    domainName: Identifier &optional;
  };
  
  type ConfirmedServiceRequest: record {
    getNameList: GetNameListRequest &optional;
    read: ReadRequest &optional;
    write: WriteRequest &optional;
    getVariableAccessAttributes: GetVariableAccessAttributesRequest &optional;
    defineNamedVariableList: DefineNamedVariableListRequest &optional;
    getNamedVariableListAttributes: GetNamedVariableListAttributesRequest &optional;
    deleteNamedVariableList: DeleteNamedVariableListRequest &optional;
  };
  
  type ConfirmedRequestPdu: record {
    invokeID: Unsigned32;
    confirmedServiceRequest: ConfirmedServiceRequest;
  };
  
  type GetNameListResponse: record {
    listOfIdentifier: vector of Identifier;
    moreFollows: bool;
  };
  
  type AccessResult: record {
    failure: DataAccessError &optional;
    success: Data &optional;
  };
  
  type ReadResponse: record {
    variableAccessSpecification: VariableAccessSpecification &optional;
    listOfAccessResult: vector of AccessResult &optional;
  };
  
  type WriteResponse: vector of record {
    failure: DataAccessError &optional;
    success: bool &optional;
  };
  
  type GetVariableAccessAttributesResponse: record {
    mmsDeletable: bool;
    typeSpecification: TypeSpecification;
  };
  
  type GetNamedVariableListAttributesResponse: record {
    mmsDeletable: bool;
    listOfVariable: vector of VariableDef;
  };
  
  type DeleteNamedVariableListResponse: record {
    numberMatched: Unsigned32;
    numberDeleted: Unsigned32;
  };
  
  type ConfirmedServiceResponse: record {
    getNameList: GetNameListResponse &optional;
    read: ReadResponse &optional;
    write: WriteResponse &optional;
    getVariableAccessAttributes: GetVariableAccessAttributesResponse &optional;
    defineNamedVariableList: DefineNamedVariableListResponse &optional;
    getNamedVariableListAttributes: GetNamedVariableListAttributesResponse &optional;
    deleteNamedVariableList: DeleteNamedVariableListResponse &optional;
  };
  
  type ConfirmedResponsePdu: record {
    invokeID: Unsigned32;
    confirmedServiceResponse: ConfirmedServiceResponse;
  };
  
  type InformationReport: record {
    variableAccessSpecification: VariableAccessSpecification;
    listOfAccessResult: vector of AccessResult;
  };
  
  type UnconfirmedService: record {
    informationReport: InformationReport &optional;
  };
  
  type UnconfirmedPDU: record {
    unconfirmedService: UnconfirmedService;
  };
  
  type ParameterSupportOptions: vector of enum {
    str1,
    str2,
    vnam,
    valt,
    vadr,
    vsca,
    tpy,
    vlis,
    real,
    cei,
  };
  
  type ServiceSupportOptions: vector of enum {
    status,
    getNameList,
    identify,
    _rename,
    read,
    write,
    getVariableAccessAttributes,
    defineNamedVariable,
    defineScatteredAccess,
    getScatteredAccessAttributes,
    deleteVariableAccess,
    defineNamedVariableList,
    getNamedVariableListAttributes,
    deleteNamedVariableList,
    defineNamedType,
    getNamedTypeAttributes,
    deleteNamedType,
    input,
    _output,
    takeControl,
    relinquishControl,
    defineSemaphore,
    deleteSemaphore,
    reportSemaphoreStatus,
    reportPoolSemaphoreStatus,
    reportSemaphoreEntryStatus,
    initiateDownloadSequence,
    downloadSegment,
    terminateDownloadSequence,
    initiateUploadSequence,
    uploadSegment,
    terminateUploadSequence,
    requestDomainDownload,
    requestDomainUpload,
    loadDomainContent,
    storeDomainContent,
    deleteDomain,
    getDomainAttributes,
    createProgramInvocation,
    deleteProgramInvocation,
    start,
    stop,
    resume,
    reset,
    kill,
    getProgramInvocationAttributes,
    obtainFile,
    defineEventCondition,
    deleteEventCondition,
    getEventConditionAttributes,
    reportEventConditionStatus,
    alterEventConditionMonitoring,
    triggerEvent,
    defineEventAction,
    deleteEventAction,
    getEventActionAttributes,
    reportEventActionStatus,
    defineEventEnrollment,
    deleteEventEnrollment,
    alterEventEnrollment,
    reportEventEnrollmentStatus,
    getEventEnrollmentAttributes,
    acknowledgeEventNotification,
    getAlarmSummary,
    getAlarmEnrollmentSummary,
    readJournal,
    writeJournal,
    initializeJournal,
    reportJournalStatus,
    createJournal,
    deleteJournal,
    getCapabilityList,
    fileOpen,
    fileRead,
    fileClose,
    fileRename,
    fileDelete,
    fileDirectory,
    unsolicitedStatus,
    informationReport,
    eventNotification,
    attachToEventCondition,
    attachToSemaphore,
    conclude,
    ServiceSupportOptions__cancel,
  };
  
  type InitRequestDetail: record {
    proposedVersionNumber: Integer16;
    proposedParameterCBB: ParameterSupportOptions;
    servicesSupportedCalling: ServiceSupportOptions;
  };
  
  type InitiateRequestPdu: record {
    localDetailCalling: Integer32 &optional;
    proposedMaxServOutstandingCalling: Integer16 &optional;
    proposedMaxServOutstandingCalled: Integer16 &optional;
    proposedDataStructureNestingLevel: Integer8 &optional;
    mmsInitRequestDetail: InitRequestDetail &optional;
  };
  
  type InitResponseDetail: record {
    negotiatedVersionNumber: Integer16;
    negotiatedParameterCBB: ParameterSupportOptions;
    servicesSupportedCalled: ServiceSupportOptions;
  };
  
  type InitiateResponsePdu: record {
    localDetailCalled: Integer32 &optional;
    negotiatedMaxServOutstandingCalling: Integer16 &optional;
    negotiatedMaxServOutstandingCalled: Integer16 &optional;
    negotiatedDataStructureNestingLevel: Integer8 &optional;
    mmsInitResponseDetail: InitResponseDetail &optional;
  };
  
  type ServiceError: record {
    errorClass: record {
      vmdState: enum {
        other = 0,
        vmd_state_conflict = 1,
        vmd_operational_problem = 2,
        domain_transfer_problem = 3,
        state_machine_id_invalid = 4,
      } &optional;
      applicationReference: enum {
        other = 0,
        aplication_unreachable = 1,
        connection_lost = 2,
        application_reference_invalid = 3,
        context_unsupported = 4,
      } &optional;
      definition: enum {
        other = 0,
        object_undefined = 1,
        invalid_address = 2,
        type_unsupported = 3,
        type_inconsistent = 4,
        object_exists = 5,
        object_attribute_inconsistent = 6,
      } &optional;
      resource: enum {
        other = 0,
        memory_unavailable = 1,
        processor_resource_unavailable = 2,
        mass_storage_unavailable = 3,
        capability_unavailable = 4,
        capability_unknown = 5,
      } &optional;
      service: enum {
        other = 0,
        primitives_out_of_sequence = 1,
        object_state_conflict = 2,
        pdu_size = 3,
        continuation_invalid = 4,
        object_constraint_conflict = 5,
      } &optional;
      servicePreempt: enum {
        other = 0,
        _timeout = 1,
        deadlock = 2,
        ServiceError__cancel = 3,
      } &optional;
      timeResolution: enum {
        other = 0,
        unsupportable_time_resolution = 1,
      } &optional;
      access: enum {
        other = 0,
        object_access_unsupported = 1,
        object_non_existent = 2,
        object_access_denied = 3,
        object_invalidated = 4,
      } &optional;
      initiate: enum {
        other = 0,
        version_incompatible = 1,
        max_segment_insufficient = 2,
        max_services_outstanding_calling_insufficient = 3,
        max_services_outstanding_called_insufficient = 4,
        service_CBB_insufficient = 5,
        parameter_CBB_insufficient = 6,
        nesting_level_insufficient = 7,
      } &optional;
      conclude: enum {
        other = 0,
        further_communication_required = 1,
      } &optional;
      _cancel: enum {
        other = 0,
        invoke_id_unknown = 1,
        cancel_not_possible = 2,
      } &optional;
      _file: enum {
        other = 0,
        filename_ambiguous = 1,
        file_busy = 2,
        filename_syntaxError = 3,
        content_type_invalid = 4,
        position_invalid = 5,
        file_acces_denied = 6,
        file_non_existent = 7,
        duplicate_filename = 8,
        insufficient_space_in_filestore = 9,
      } &optional;
      others: int &optional;
    };
    additionalCode: int &optional;
    additionalDescription: string &optional;
  };
  
  type InitiateErrorPdu: ServiceError;
  
  type MmsPdu: record {
    confirmedRequestPdu: ConfirmedRequestPdu &optional;
    confirmedResponsePdu: ConfirmedResponsePdu &optional;
    unconfirmedPDU: UnconfirmedPDU &optional;
    initiateRequestPdu: InitiateRequestPdu &optional;
    initiateResponsePdu: InitiateResponsePdu &optional;
    initiateErrorPdu: InitiateErrorPdu &optional;
  };
  
  type ScatteredAccessDescription: vector of record {
    componentName: Identifier &optional;
    variableSpecification: VariableSpecification &optional;
    alternateAccess: AlternateAccess &optional;
  };
  
  
  # ======== SELF DEPENDENT TYPES =======
  redef record AlternateAccess += {
    selectAlternateAccess: record {
      accessSelection: record {
        component: Identifier &optional;
        index: Unsigned32 &optional;
        indexRange: record {
          lowIndex: Unsigned32;
          numberOfElements: Unsigned32;
        } &optional;
        allElements: bool &optional;
      };
      alternateAccess: AlternateAccess;
    } &optional;
    component: Identifier &optional;
    index: Unsigned32 &optional;
    indexRange: IndexRangeSeq &optional;
    allElements: bool &optional;
    named: record {
      componentName: Identifier;
      accesst: AlternateAccessSelection;
    } &optional;
  };
  
  redef record AlternateAccessSelection += {
    selectAlternateAccess: record {
      component: Identifier;
      index: Unsigned32;
      indexRange: record {
        lowIndex: Unsigned32;
        numberOfElements: Unsigned32;
      };
      allElements: bool;
      alternateAccess: AlternateAccess;
    } &optional;
    component: Identifier &optional;
    index: Unsigned32 &optional;
    indexRange: IndexRangeSeq &optional;
    allElements: bool &optional;
  };
  
  redef record Data += {
    array: DataSequence &optional;
    structure: DataSequence &optional;
    boolean: bool &optional;
    bitString: string &optional;
    integer: int &optional;
    unsigned: int &optional;
    floatingPoint: FloatingPoint &optional;
    octetString: string &optional;
    visibleString: string &optional;
    binaryTime: TimeOfDay &optional;
    mmsString: MMSString &optional;
    utcTime: UtcTime &optional;
  };
  
  redef record TypeSpecification += {
    array: record {
      packed: bool;
      numberOfElements: Unsigned32;
      elementType: TypeSpecification;
    } &optional;
    structure: record {
      packed: bool;
      components: vector of StructComponent;
    } &optional;
    boolean: bool &optional;
    bitString: Integer32 &optional;
    integer: Unsigned8 &optional;
    unsigned: Unsigned8 &optional;
    floatingPoint: record {
      formatWidth: Unsigned8;
      exponentWidth: Unsigned8;
    } &optional;
    octetString: Integer32 &optional;
    visibleString: Integer32 &optional;
    binaryTime: bool &optional;
    mmsString: Integer32 &optional;
    utcTime: bool &optional;
  };
  
  redef record StructComponent += {
    componentName: Identifier &optional;
    componentType: TypeSpecification &optional;
  };
  
}
