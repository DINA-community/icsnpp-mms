#THIS CODE IS GENERATED. DON'T CHANGE MANUALLY!
module mms;
export {
  
  # ======== PRIMITIVE TYPES =======
  type Unsigned32: int;
  
  type Identifier: string;
  
  type Unsigned8: int;
  
  type Status_Request: bool;
  
  type ObjectClass: enum {
    nammedVariable = 0,
    ObjectClass_scatteredAccess = 1,
    ObjectClass_namedVariableList = 2,
    ObjectClass_namedType = 3,
    ObjectClass_semaphore = 4,
    ObjectClass_eventCondition = 5,
    ObjectClass_eventAction = 6,
    ObjectClass_eventEnrollment = 7,
    ObjectClass_journal = 8,
    ObjectClass__domain = 9,
    ObjectClass_programInvocation = 10,
    ObjectClass_operatorStation = 11,
  };
  
  type Identify_Request: bool;
  
  type Integer32: int;
  
  type FloatingPoint: string;
  
  type TimeOfDay: string;
  
  type MMSString: string;
  
  type UtcTime: string;
  
  type Unsigned16: int;
  
  type ObtainFile_Error: enum {
    ObtainFile_Error_source_file = 0,
    ObtainFile_Error_destination_file = 1,
  };
  
  type ProgramInvocationState: enum {
    ProgramInvocationState_non_existent = 0,
    unrunable = 1,
    ProgramInvocationState_idle = 2,
    running = 3,
    stopped = 4,
    starting = 5,
    stopping = 6,
    resuming = 7,
    resetting = 8,
  };
  
  type FileRename_Error: enum {
    FileRename_Error_source_file = 0,
    FileRename_Error_destination_file = 1,
  };
  
  type EC_Class: enum {
    network_triggered = 0,
    monitored = 1,
  };
  
  type AlarmAckRule: enum {
    AlarmAckRule_none = 0,
    AlarmAckRule_simple = 1,
    ack_active = 2,
    ack_all = 3,
  };
  
  type EC_State: enum {
    EC_State_disabled = 0,
    EC_State_idle = 1,
    EC_State_active = 2,
  };
  
  type JOU_Additional_Detail: bool;
  
  type Rename_Response: bool;
  
  type DataAccessError: enum {
    DataAccessError_object_invalidated = 0,
    hardware_fault = 1,
    temporarily_unavailable = 2,
    DataAccessError_object_access_denied = 3,
    DataAccessError_object_undefined = 4,
    DataAccessError_invalid_address = 5,
    DataAccessError_type_unsupported = 6,
    DataAccessError_type_inconsistent = 7,
    DataAccessError_object_attribute_inconsistent = 8,
    DataAccessError_object_access_unsupported = 9,
    DataAccessError_object_non_existent = 10,
    object_value_invalid = 11,
  };
  
  type DefineNamedVariable_Response: bool;
  
  type DefineScatteredAccess_Response: bool;
  
  type DefineNamedVariableList_Response: bool;
  
  type DefineNamedType_Response: bool;
  
  type Input_Response: string;
  
  type Output_Response: bool;
  
  type RelinquishControl_Response: bool;
  
  type DefineSemaphore_Response: bool;
  
  type DeleteSemaphore_Response: bool;
  
  type InitiateDownloadSequence_Response: bool;
  
  type TerminateDownloadSequence_Response: bool;
  
  type TerminateUploadSequence_Response: bool;
  
  type RequestDomainDownload_Response: bool;
  
  type RequestDomainUpload_Response: bool;
  
  type LoadDomainContent_Response: bool;
  
  type StoreDomainContent_Response: bool;
  
  type DeleteDomain_Response: bool;
  
  type DomainState: enum {
    DomainState_non_existent = 0,
    loading = 1,
    ready = 2,
    in_use = 3,
    complete = 4,
    incomplete = 5,
    d1 = 7,
    d2 = 8,
    d3 = 9,
    d4 = 10,
    d5 = 11,
    d6 = 12,
    d7 = 13,
    d8 = 14,
    d9 = 15,
  };
  
  type Integer8: int;
  
  type CreateProgramInvocation_Response: bool;
  
  type DeleteProgramInvocation_Response: bool;
  
  type Start_Response: bool;
  
  type Stop_Response: bool;
  
  type Resume_Response: bool;
  
  type Reset_Response: bool;
  
  type Kill_Response: bool;
  
  type ObtainFile_Response: bool;
  
  type DefineEventCondition_Response: bool;
  
  type AlterEventConditionMonitoring_Response: bool;
  
  type TriggerEvent_Response: bool;
  
  type DefineEventAction_Response: bool;
  
  type DefineEventEnrollment_Response: bool;
  
  type EE_State: enum {
    EE_State_disabled = 0,
    EE_State_idle = 1,
    EE_State_active = 2,
    activeNoAckA = 3,
    idleNoAckI = 4,
    idleNoAckA = 5,
    idleAcked = 6,
    activeAcked = 7,
  };
  
  type EE_Duration: enum {
    current = 0,
    permanent = 1,
  };
  
  type EE_Class: enum {
    EE_Class_modifier = 0,
    notification = 1,
  };
  
  type AcknowledgeEventNotification_Response: bool;
  
  type WriteJournal_Response: bool;
  
  type CreateJournal_Response: bool;
  
  type DeleteJournal_Response: bool;
  
  type FileClose_Response: bool;
  
  type FileRename_Response: bool;
  
  type FileDelete_Response: bool;
  
  type Integer16: int;
  
  type Conclude_RequestPDU: bool;
  
  type Conclude_ResponsePDU: bool;
  
  
  # ======== FORWARD DECLARATIONS =======
  type TypeSpecification: record {};
  type VariableSpecification: record {};
  type AlternateAccess: record {};
  type AlternateAccessSelection: record {};
  type ScatteredAccessDescription: record {};
  type Data: record {};
  
  # ======== COMPLEX TYPES =======
  type ReportedOptFlds: vector of enum {
    reserved,
    sequence_number,
    report_time_stamp,
    reason_for_inclusion,
    data_set_name,
    data_reference,
    buffer_overflow,
    entryID,
    conf_revision,
    segmentation,
  };
  
  type ObjectName: record {
    vmd_specific: Identifier &optional;
    domain_specific: record {
      domainId: Identifier;
      itemId: Identifier;
    } &optional;
    aa_specific: Identifier &optional;
  };
  
  type Transitions: vector of enum {
    idle_to_disabled,
    active_to_disabled,
    disabled_to_idle,
    active_to_idle,
    disabled_to_active,
    idle_to_active,
    any_to_deleted,
  };
  
  type AttachToEventCondition: record {
    eventEnrollmentName: ObjectName;
    eventConditionName: ObjectName;
    causingTransitions: Transitions;
    acceptableDelay: Unsigned32 &optional;
  };
  
  type Priority: Unsigned8;
  
  type AttachToSemaphore: record {
    semaphoreName: ObjectName;
    namedToken: Identifier &optional;
    priority: Priority;
    acceptableDelay: Unsigned32 &optional;
    controlTimeOut: Unsigned32 &optional;
    abortOnTimeOut: bool &optional;
    relinquishIfConnectionLost: bool;
  };
  
  type Modifier: record {
    attach_To_Event_Condition: AttachToEventCondition &optional;
    attach_To_Semaphore: AttachToSemaphore &optional;
  };
  
  type ObjectScope: record {
    vmdSpecific: bool &optional;
    domainSpecific: Identifier &optional;
    aaSpecific: bool &optional;
  };
  
  type GetNameList_Request: record {
    extendedObjectClass: record {
      objectClass: ObjectClass &optional;
    };
    objectScope: ObjectScope;
    continueAfter: Identifier &optional;
  };
  
  type Rename_Request: record {
    extendedObjectClass: record {
      objectClass: enum {
        namedVariable = 0,
        Rename_Request_scatteredAccess = 1,
        Rename_Request_namedVariableList = 2,
        Rename_Request_namedType = 3,
        Rename_Request_semaphore = 4,
        Rename_Request_eventCondition = 5,
        Rename_Request_eventAction = 6,
        Rename_Request_eventEnrollment = 7,
        Rename_Request_journal = 8,
        Rename_Request__domain = 9,
        Rename_Request_programInvocation = 10,
        Rename_Request_operatorStation = 11,
      } &optional;
    };
    currentName: ObjectName;
    newIdentifier: Identifier;
  };
  
  type Address: record {
    numericAddress: Unsigned32 &optional;
    symbolicAddress: string &optional;
    unconstrainedAddress: string &optional;
  };
  
  type VariableAccessSpecification: record {
    listOfVariable: vector of record {
      variableSpecification: VariableSpecification;
      alternateAccess: AlternateAccess &optional;
    } &optional;
    variableListName: ObjectName &optional;
  };
  
  type Read_Request: record {
    specificationWithResult: bool;
    variableAccessSpecificatn: VariableAccessSpecification;
  };
  
  type Write_Request: record {
    variableAccessSpecificatn: VariableAccessSpecification;
    listOfData: vector of Data;
  };
  
  type GetVariableAccessAttributes_Request: record {
    name: ObjectName &optional;
    address: Address &optional;
  };
  
  type DefineNamedVariable_Request: record {
    variableName: ObjectName;
    address: Address;
    typeSpecification: TypeSpecification &optional;
  };
  
  type DefineScatteredAccess_Request: record {
    scatteredAccessName: ObjectName;
    scatteredAccessDescription: ScatteredAccessDescription;
  };
  
  type GetScatteredAccessAttributes_Request: ObjectName;
  
  type DeleteVariableAccess_Request: record {
    scopeOfDelete: enum {
      DeleteVariableAccess_Request_specific = 0,
      DeleteVariableAccess_Request_aa_specific = 1,
      DeleteVariableAccess_Request__domain = 2,
      DeleteVariableAccess_Request_vmd = 3,
    };
    listOfName: vector of ObjectName &optional;
    domainName: Identifier &optional;
  };
  
  type DefineNamedVariableList_Request: record {
    variableListName: ObjectName;
    listOfVariable: vector of record {
      variableSpecification: VariableSpecification;
      alternateAccess: AlternateAccess &optional;
    };
  };
  
  type GetNamedVariableListAttributes_Request: ObjectName;
  
  type DeleteNamedVariableList_Request: record {
    scopeOfDelete: enum {
      DeleteNamedVariableList_Request_specific = 0,
      DeleteNamedVariableList_Request_aa_specific = 1,
      DeleteNamedVariableList_Request__domain = 2,
      DeleteNamedVariableList_Request_vmd = 3,
    };
    listOfVariableListName: vector of ObjectName &optional;
    domainName: Identifier &optional;
  };
  
  type DefineNamedType_Request: record {
    typeName: ObjectName;
    typeSpecification: TypeSpecification;
  };
  
  type GetNamedTypeAttributes_Request: ObjectName;
  
  type DeleteNamedType_Request: record {
    scopeOfDelete: enum {
      DeleteNamedType_Request_specific = 0,
      DeleteNamedType_Request_aa_specific = 1,
      DeleteNamedType_Request__domain = 2,
      DeleteNamedType_Request_vmd = 3,
    };
    listOfTypeName: vector of ObjectName &optional;
    domainName: Identifier &optional;
  };
  
  type Input_Request: record {
    operatorStationName: Identifier;
    echo: bool;
    listOfPromptData: vector of string &optional;
    inputTimeOut: Unsigned32 &optional;
  };
  
  type Output_Request: record {
    operatorStationName: Identifier;
    listOfOutputData: vector of string;
  };
  
  type TakeControl_Request: record {
    semaphoreName: ObjectName;
    namedToken: Identifier &optional;
    priority: Priority;
    acceptableDelay: Unsigned32 &optional;
    controlTimeOut: Unsigned32 &optional;
    abortOnTimeOut: bool &optional;
    relinquishIfConnectionLost: bool;
  };
  
  type RelinquishControl_Request: record {
    semaphoreName: ObjectName;
    namedToken: Identifier &optional;
  };
  
  type DefineSemaphore_Request: record {
    semaphoreName: ObjectName;
    numbersOfTokens: Unsigned16;
  };
  
  type DeleteSemaphore_Request: ObjectName;
  
  type ReportSemaphoreStatus_Request: ObjectName;
  
  type ReportPoolSemaphoreStatus_Request: record {
    semaphoreName: ObjectName;
    nameToStartAfter: Identifier &optional;
  };
  
  type ReportSemaphoreEntryStatus_Request: record {
    semaphoreName: ObjectName;
    state: enum {
      queued = 0,
      owner = 1,
      hung = 2,
    };
    entryIdToStartAfter: string &optional;
  };
  
  type InitiateDownloadSequence_Request: record {
    domainName: Identifier;
    listOfCapabilities: vector of string;
    sharable: bool;
  };
  
  type DownloadSegment_Request: Identifier;
  
  type Start_Error: ProgramInvocationState;
  
  type Stop_Error: ProgramInvocationState;
  
  type Resume_Error: ProgramInvocationState;
  
  type Reset_Error: ProgramInvocationState;
  
  type DeleteVariableAccess_Error: Unsigned32;
  
  type DeleteNamedVariableList_Error: Unsigned32;
  
  type DeleteNamedType_Error: Unsigned32;
  
  type DefineEventEnrollment_Error: ObjectName;
  
  type DefineEventConditionList_Error: ObjectName;
  
  type AddEventConditionListReference_Error: ObjectName;
  
  type RemoveEventConditionListReference_Error: record {
    eventCondition: ObjectName &optional;
    eventConditionList: ObjectName &optional;
  };
  
  type InitiateUnitControl_Error: record {
    _domain: Identifier &optional;
    programInvocation: Identifier &optional;
  };
  
  type StartUnitControl_Error: record {
    programInvocationName: Identifier;
    programInvocationState: ProgramInvocationState;
  };
  
  type StopUnitControl_Error: record {
    programInvocationName: Identifier;
    programInvocationState: ProgramInvocationState;
  };
  
  type DeleteUnitControl_Error: record {
    _domain: Identifier &optional;
    programInvocation: Identifier &optional;
  };
  
  type LoadUnitControlFromFile_Error: record {
    none: bool &optional;
    _domain: Identifier &optional;
    programInvocation: Identifier &optional;
  };
  
  type AdditionalService_Error: record {
    defineEcl: DefineEventConditionList_Error &optional;
    addECLReference: AddEventConditionListReference_Error &optional;
    removeECLReference: RemoveEventConditionListReference_Error &optional;
    initiateUC: InitiateUnitControl_Error &optional;
    startUC: StartUnitControl_Error &optional;
    stopUC: StopUnitControl_Error &optional;
    deleteUC: DeleteUnitControl_Error &optional;
    loadUCFromFile: LoadUnitControlFromFile_Error &optional;
  };
  
  type ChangeAccessControl_Error: Unsigned32;
  
  type ServiceError: record {
    errorClass: record {
      vmd_state: enum {
        ServiceError_other = 0,
        vmd_state_conflict = 1,
        vmd_operational_problem = 2,
        domain_transfer_problem = 3,
        state_machine_id_invalid = 4,
      } &optional;
      application_reference: enum {
        ServiceError_other = 0,
        aplication_unreachable = 1,
        connection_lost = 2,
        application_reference_invalid = 3,
        context_unsupported = 4,
      } &optional;
      definition: enum {
        ServiceError_other = 0,
        ServiceError_object_undefined = 1,
        ServiceError_invalid_address = 2,
        ServiceError_type_unsupported = 3,
        ServiceError_type_inconsistent = 4,
        object_exists = 5,
        ServiceError_object_attribute_inconsistent = 6,
      } &optional;
      resource: enum {
        ServiceError_other = 0,
        memory_unavailable = 1,
        processor_resource_unavailable = 2,
        mass_storage_unavailable = 3,
        capability_unavailable = 4,
        capability_unknown = 5,
      } &optional;
      service: enum {
        ServiceError_other = 0,
        primitives_out_of_sequence = 1,
        object_sate_conflict = 2,
        pdu_size = 3,
        continuation_invalid = 4,
        object_constraint_conflict = 5,
      } &optional;
      service_preempt: enum {
        ServiceError_other = 0,
        _timeout = 1,
        deadlock = 2,
        ServiceError__cancel = 3,
      } &optional;
      time_resolution: enum {
        ServiceError_other = 0,
        unsupportable_time_resolution = 1,
      } &optional;
      access: enum {
        ServiceError_other = 0,
        ServiceError_object_access_unsupported = 1,
        ServiceError_object_non_existent = 2,
        ServiceError_object_access_denied = 3,
        ServiceError_object_invalidated = 4,
      } &optional;
      initiate: enum {
        ServiceError_other = 0,
        version_incompatible = 1,
        max_segment_insufficient = 2,
        max_services_outstanding_calling_insufficient = 3,
        max_services_outstanding_called_insufficient = 4,
        service_CBB_insufficient = 5,
        parameter_CBB_insufficient = 6,
        nesting_level_insufficient = 7,
      } &optional;
      conclude: enum {
        ServiceError_other = 0,
        further_communication_required = 1,
      } &optional;
      _cancel: enum {
        ServiceError_other = 0,
        invoke_id_unknown = 1,
        cancel_not_possible = 2,
      } &optional;
      _file: enum {
        ServiceError_other = 0,
        filename_ambiguous = 1,
        file_busy = 2,
        filename_syntax_error = 3,
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
    serviceSpecificInformation: record {
      obtainFile: ObtainFile_Error &optional;
      start: Start_Error &optional;
      stop: Stop_Error &optional;
      resume: Resume_Error &optional;
      reset: Reset_Error &optional;
      deleteVariableAccess: DeleteVariableAccess_Error &optional;
      deleteNamedVariableList: DeleteNamedVariableList_Error &optional;
      deleteNamedType: DeleteNamedType_Error &optional;
      defineEventEnrollment_Error: DefineEventEnrollment_Error &optional;
      fileRename: FileRename_Error &optional;
      additionalService: AdditionalService_Error &optional;
      changeAccessControl: ChangeAccessControl_Error &optional;
    } &optional;
  };
  
  type TerminateDownloadSequence_Request: record {
    domainName: Identifier;
    discard: ServiceError &optional;
  };
  
  type InitiateUploadSequence_Request: Identifier;
  
  type UploadSegment_Request: Integer32;
  
  type TerminateUploadSequence_Request: Integer32;
  
  type FileName: vector of string;
  
  type RequestDomainDownload_Request: record {
    domainName: Identifier;
    listOfCapabilities: vector of string &optional;
    sharable: bool;
    fileName: FileName;
  };
  
  type RequestDomainUpload_Request: record {
    domainName: Identifier;
    fileName: FileName;
  };
  
  type LoadDomainContent_Request: record {
    domainName: Identifier;
    listOfCapabilities: vector of string &optional;
    sharable: bool;
    fileName: FileName;
  };
  
  type StoreDomainContent_Request: record {
    domainName: Identifier;
    filenName: FileName;
  };
  
  type DeleteDomain_Request: Identifier;
  
  type GetDomainAttributes_Request: Identifier;
  
  type CreateProgramInvocation_Request: record {
    programInvocationName: Identifier;
    listOfDomainName: vector of Identifier;
    reusable: bool;
    monitorType: bool &optional;
  };
  
  type DeleteProgramInvocation_Request: Identifier;
  
  type EXTERNALt: record {
    direct_reference: string &optional;
    indirect_reference: int &optional;
    data_value_descriptor: string &optional;
    encoding: record {
      single_ASN1_type: string &optional;
      octet_aligned: string &optional;
      arbitrary: string &optional;
    };
  };
  
  type Start_Request: record {
    programInvocationName: Identifier;
    executionArgument: record {
      simpleString: string &optional;
      encodedString: EXTERNALt &optional;
    } &optional;
  };
  
  type Stop_Request: record {
    programInvocationName: Identifier;
  };
  
  type Resume_Request: record {
    programInvocationName: Identifier;
    executionArgument: record {
      simpleString: string &optional;
      encodedString: EXTERNALt &optional;
    } &optional;
  };
  
  type Reset_Request: record {
    programInvocationName: Identifier;
  };
  
  type Kill_Request: record {
    programInvocationName: Identifier;
  };
  
  type GetProgramInvocationAttributes_Request: Identifier;
  
  type ObtainFile_Request: record {
    sourceFile: FileName;
    destinationFile: FileName;
  };
  
  type DefineEventCondition_Request: record {
    eventConditionName: ObjectName;
    class: EC_Class;
    prio_rity: Priority;
    severity: Unsigned8;
    alarmSummaryReports: bool &optional;
    monitoredVariable: VariableSpecification &optional;
    evaluationInterval: Unsigned32 &optional;
  };
  
  type DeleteEventCondition_Request: record {
    specific: vector of ObjectName &optional;
    aa_specific: bool &optional;
    _domain: Identifier &optional;
    vmd: bool &optional;
  };
  
  type GetEventConditionAttributes_Request: ObjectName;
  
  type ReportEventConditionStatus_Request: ObjectName;
  
  type AlterEventConditionMonitoring_Request: record {
    eventConditionName: ObjectName;
    enabled: bool &optional;
    priority: Priority &optional;
    alarmSummaryReports: bool &optional;
    evaluationInterval: Unsigned32 &optional;
  };
  
  type TriggerEvent_Request: record {
    eventConditionName: ObjectName;
    priority: Priority &optional;
  };
  
  type DefineEventAction_Request: record {
    eventActionName: ObjectName;
    listOfModifier: vector of Modifier &optional;
  };
  
  type DeleteEventAction_Request: record {
    specific: vector of ObjectName &optional;
    aa_specific: bool &optional;
    _domain: Identifier &optional;
    vmd: bool &optional;
  };
  
  type GetEventActionAttributes_Request: ObjectName;
  
  type ReportEventActionStatus_Request: ObjectName;
  
  type DefineEventEnrollment_Request: record {
    eventEnrollmentName: ObjectName;
    eventConditionName: ObjectName;
    eventConditionTransition: Transitions;
    alarmAcknowledgementRule: AlarmAckRule;
    eventActionName: ObjectName &optional;
  };
  
  type DeleteEventEnrollment_Request: record {
    specific: vector of ObjectName &optional;
    ec: ObjectName &optional;
    ea: ObjectName &optional;
  };
  
  type AlterEventEnrollment_Request: record {
    eventEnrollmentName: ObjectName;
    eventConditionTransitions: Transitions &optional;
    alarmAcknowledgmentRule: AlarmAckRule &optional;
  };
  
  type ReportEventEnrollmentStatus_Request: ObjectName;
  
  type GetEventEnrollmentAttributes_Request: record {
    scopeOfRequest: enum {
      GetEventEnrollmentAttributes_Request_specific = 0,
      client = 1,
      ec = 2,
      ea = 3,
    };
    eventEnrollmentNames: vector of ObjectName &optional;
    eventConditionName: ObjectName &optional;
    eventActionName: ObjectName &optional;
    continueAfter: ObjectName &optional;
  };
  
  type EventTime: record {
    timeOfDayT: TimeOfDay &optional;
    timeSequenceIdentifier: Unsigned32 &optional;
  };
  
  type AcknowledgeEventNotification_Request: record {
    eventEnrollmentName: ObjectName;
    acknowledgedState: EC_State;
    timeOfAcknowledgedTransition: EventTime;
  };
  
  type GetAlarmSummary_Request: record {
    enrollmentsOnly: bool;
    activeAlarmsOnly: bool;
    acknowledgmentFilter: enum {
      GetAlarmSummary_Request_not_acked = 0,
      GetAlarmSummary_Request_acked = 1,
      GetAlarmSummary_Request_all = 2,
    };
    severityFilter: record {
      mostSevere: Unsigned8;
      leastSevere: Unsigned8;
    } &optional;
    continueAfter: ObjectName &optional;
  };
  
  type GetAlarmEnrollmentSummary_Request: record {
    enrollmentsOnly: bool;
    activeAlarmsOnly: bool;
    acknowledgmentFilter: enum {
      GetAlarmEnrollmentSummary_Request_not_acked = 0,
      GetAlarmEnrollmentSummary_Request_acked = 1,
      GetAlarmEnrollmentSummary_Request_all = 2,
    };
    severityFilter: record {
      mostSevere: Unsigned8;
      leastSevere: Unsigned8;
    } &optional;
    continueAfter: ObjectName &optional;
  };
  
  type ReadJournal_Request: record {
    journalName: ObjectName;
    rangeStartSpecification: record {
      startingTime: TimeOfDay &optional;
      startingEntry: string &optional;
    } &optional;
    rangeStopSpecification: record {
      endingTime: TimeOfDay &optional;
      numberOfEntries: Integer32 &optional;
    } &optional;
    listOfVariables: vector of string &optional;
    entryToStartAfter: record {
      timeSpecification: TimeOfDay;
      entrySpecification: string;
    };
  };
  
  type EntryContent: record {
    occurenceTime: TimeOfDay;
    additionalDetail: JOU_Additional_Detail &optional;
    entryForm: record {
      data: record {
        _event: record {
          eventConditionName: ObjectName;
          currentState: EC_State;
        } &optional;
        listOfVariables: vector of record {
          variableTag: string;
          valueSpecification: Data;
        } &optional;
      } &optional;
      annotation: string &optional;
    };
  };
  
  type WriteJournal_Request: record {
    journalName: ObjectName;
    listOfJournalEntry: vector of EntryContent;
  };
  
  type InitializeJournal_Request: record {
    journalName: ObjectName;
    limitSpecification: record {
      limitingTime: TimeOfDay;
      limitingEntry: string &optional;
    } &optional;
  };
  
  type ReportJournalStatus_Request: ObjectName;
  
  type CreateJournal_Request: record {
    journalName: ObjectName;
  };
  
  type DeleteJournal_Request: record {
    journalName: ObjectName;
  };
  
  type GetCapabilityList_Request: record {
    continueAfter: string &optional;
  };
  
  type FileOpen_Request: record {
    fileName: FileName;
    initialPosition: Unsigned32;
  };
  
  type FileRead_Request: Integer32;
  
  type FileClose_Request: Integer32;
  
  type FileRename_Request: record {
    currentFileName: FileName;
    newFileName: FileName;
  };
  
  type FileDelete_Request: FileName;
  
  type FileDirectory_Request: record {
    fileSpecification: FileName &optional;
    continueAfter: FileName &optional;
  };
  
  type ConfirmedServiceRequest: record {
    status: Status_Request &optional;
    getNameList: GetNameList_Request &optional;
    identify: Identify_Request &optional;
    _rename: Rename_Request &optional;
    read: Read_Request &optional;
    write: Write_Request &optional;
    getVariableAccessAttributes: GetVariableAccessAttributes_Request &optional;
    defineNamedVariable: DefineNamedVariable_Request &optional;
    defineScatteredAccess: DefineScatteredAccess_Request &optional;
    getScatteredAccessAttributes: GetScatteredAccessAttributes_Request &optional;
    deleteVariableAccess: DeleteVariableAccess_Request &optional;
    defineNamedVariableList: DefineNamedVariableList_Request &optional;
    getNamedVariableListAttributes: GetNamedVariableListAttributes_Request &optional;
    deleteNamedVariableList: DeleteNamedVariableList_Request &optional;
    defineNamedType: DefineNamedType_Request &optional;
    getNamedTypeAttributes: GetNamedTypeAttributes_Request &optional;
    deleteNamedType: DeleteNamedType_Request &optional;
    input: Input_Request &optional;
    _output: Output_Request &optional;
    takeControl: TakeControl_Request &optional;
    relinquishControl: RelinquishControl_Request &optional;
    defineSemaphore: DefineSemaphore_Request &optional;
    deleteSemaphore: DeleteSemaphore_Request &optional;
    reportSemaphoreStatus: ReportSemaphoreStatus_Request &optional;
    reportPoolSemaphoreStatus: ReportPoolSemaphoreStatus_Request &optional;
    reportSemaphoreEntryStatus: ReportSemaphoreEntryStatus_Request &optional;
    initiateDownloadSequence: InitiateDownloadSequence_Request &optional;
    downloadSegment: DownloadSegment_Request &optional;
    terminateDownloadSequence: TerminateDownloadSequence_Request &optional;
    initiateUploadSequence: InitiateUploadSequence_Request &optional;
    uploadSegment: UploadSegment_Request &optional;
    terminateUploadSequence: TerminateUploadSequence_Request &optional;
    requestDomainDownload: RequestDomainDownload_Request &optional;
    requestDomainUpload: RequestDomainUpload_Request &optional;
    loadDomainContent: LoadDomainContent_Request &optional;
    storeDomainContent: StoreDomainContent_Request &optional;
    deleteDomain: DeleteDomain_Request &optional;
    getDomainAttributes: GetDomainAttributes_Request &optional;
    createProgramInvocation: CreateProgramInvocation_Request &optional;
    deleteProgramInvocation: DeleteProgramInvocation_Request &optional;
    start: Start_Request &optional;
    stop: Stop_Request &optional;
    resume: Resume_Request &optional;
    reset: Reset_Request &optional;
    kill: Kill_Request &optional;
    getProgramInvocationAttributes: GetProgramInvocationAttributes_Request &optional;
    obtainFile: ObtainFile_Request &optional;
    defineEventCondition: DefineEventCondition_Request &optional;
    deleteEventCondition: DeleteEventCondition_Request &optional;
    getEventConditionAttributes: GetEventConditionAttributes_Request &optional;
    reportEventConditionStatus: ReportEventConditionStatus_Request &optional;
    alterEventConditionMonitoring: AlterEventConditionMonitoring_Request &optional;
    triggerEvent: TriggerEvent_Request &optional;
    defineEventAction: DefineEventAction_Request &optional;
    deleteEventAction: DeleteEventAction_Request &optional;
    getEventActionAttributes: GetEventActionAttributes_Request &optional;
    reportEventActionStatus: ReportEventActionStatus_Request &optional;
    defineEventEnrollment: DefineEventEnrollment_Request &optional;
    deleteEventEnrollment: DeleteEventEnrollment_Request &optional;
    alterEventEnrollment: AlterEventEnrollment_Request &optional;
    reportEventEnrollmentStatus: ReportEventEnrollmentStatus_Request &optional;
    getEventEnrollmentAttributes: GetEventEnrollmentAttributes_Request &optional;
    acknowledgeEventNotification: AcknowledgeEventNotification_Request &optional;
    getAlarmSummary: GetAlarmSummary_Request &optional;
    getAlarmEnrollmentSummary: GetAlarmEnrollmentSummary_Request &optional;
    readJournal: ReadJournal_Request &optional;
    writeJournal: WriteJournal_Request &optional;
    initializeJournal: InitializeJournal_Request &optional;
    reportJournalStatus: ReportJournalStatus_Request &optional;
    createJournal: CreateJournal_Request &optional;
    deleteJournal: DeleteJournal_Request &optional;
    getCapabilityList: GetCapabilityList_Request &optional;
    fileOpen: FileOpen_Request &optional;
    fileRead: FileRead_Request &optional;
    fileClose: FileClose_Request &optional;
    fileRename: FileRename_Request &optional;
    fileDelete: FileDelete_Request &optional;
    fileDirectory: FileDirectory_Request &optional;
  };
  
  type CS_Request_Detail: record {
    foo: int &optional;
  };
  
  type Confirmed_RequestPDU: record {
    invokeID: Unsigned32;
    listOfModifier: vector of Modifier &optional;
    confirmedServiceRequest: ConfirmedServiceRequest;
    cs_request_detail: CS_Request_Detail &optional;
  };
  
  type Status_Response: record {
    vmdLogicalStatus: enum {
      state_changes_allowed = 0,
      no_state_changes_allowed = 1,
      limited_services_allowed = 2,
      support_services_allowed = 3,
    };
    vmdPhysicalStatus: enum {
      operational = 0,
      partially_operational = 1,
      inoperable = 2,
      needs_commissioning = 3,
    };
    localDetail: string &optional;
  };
  
  type GetNameList_Response: record {
    listOfIdentifier: vector of Identifier;
    moreFollows: bool;
  };
  
  type Identify_Response: record {
    vendorName: string;
    modelName: string;
    revision: string;
    listOfAbstractSyntaxes: vector of string &optional;
  };
  
  type AccessResult: record {
    failure: DataAccessError &optional;
    success: Data &optional;
  };
  
  type Read_Response: record {
    variableAccessSpecificatn: VariableAccessSpecification &optional;
    listOfAccessResult: vector of AccessResult;
  };
  
  type Write_Response: vector of record {
    failure: DataAccessError &optional;
    success: bool &optional;
  };
  
  type GetVariableAccessAttributes_Response: record {
    mmsDeletable: bool;
    address: Address &optional;
    typeSpecification: TypeSpecification;
  };
  
  type GetScatteredAccessAttributes_Response: record {
    mmsDeletable: bool;
    scatteredAccessDescription: ScatteredAccessDescription;
  };
  
  type DeleteVariableAccess_Response: record {
    numberMatched: Unsigned32;
    numberDeleted: Unsigned32;
  };
  
  type GetNamedVariableListAttributes_Response: record {
    mmsDeletable: bool;
    listOfVariable: vector of record {
      variableSpecification: VariableSpecification;
      alternateAccess: AlternateAccess &optional;
    };
  };
  
  type DeleteNamedVariableList_Response: record {
    numberMatched: Unsigned32;
    numberDeleted: Unsigned32;
  };
  
  type GetNamedTypeAttributes_Response: record {
    mmsDeletable: bool;
    typeSpecification: TypeSpecification;
  };
  
  type DeleteNamedType_Response: record {
    numberMatched: Unsigned32;
    numberDeleted: Unsigned32;
  };
  
  type TakeControl_Response: record {
    noResult: bool &optional;
    namedToken: Identifier &optional;
  };
  
  type ReportSemaphoreStatus_Response: record {
    mmsDeletable: bool;
    class: enum {
      token = 0,
      pool = 1,
    };
    numberOfTokens: Unsigned16;
    numberOfOwnedTokens: Unsigned16;
    numberOfHungTokens: Unsigned16;
  };
  
  type ReportPoolSemaphoreStatus_Response: record {
    listOfNamedTokens: vector of record {
      freeNamedToken: Identifier &optional;
      ownedNamedToken: Identifier &optional;
      hungNamedToken: Identifier &optional;
    };
    moreFollows: bool;
  };
  
  type SemaphoreEntry: record {
    entryId: string;
    entryClass: enum {
      SemaphoreEntry_simple = 0,
      SemaphoreEntry_modifier = 1,
    };
    namedToken: Identifier &optional;
    priority: Priority;
    remainingTimeOut: Unsigned32 &optional;
    abortOnTimeOut: bool &optional;
    relinquishIfConnectionLost: bool;
  };
  
  type ReportSemaphoreEntryStatus_Response: record {
    listOfSemaphoreEntry: vector of SemaphoreEntry;
    moreFollows: bool;
  };
  
  type DownloadSegment_Response: record {
    loadData: record {
      non_coded: string &optional;
      coded: EXTERNALt &optional;
    };
    moreFollows: bool;
  };
  
  type InitiateUploadSequence_Response: record {
    ulsmID: Integer32;
    listOfCapabilities: vector of string;
  };
  
  type UploadSegment_Response: record {
    loadData: record {
      non_coded: string &optional;
      coded: EXTERNALt &optional;
    };
    moreFollows: bool;
  };
  
  type GetDomainAttributes_Response: record {
    listOfCapabilities: vector of string;
    state: DomainState;
    mmsDeletable: bool;
    sharable: bool;
    listOfProgramInvocations: vector of Identifier;
    uploadInProgress: Integer8;
  };
  
  type GetProgramInvocationAttributes_Response: record {
    state: ProgramInvocationState;
    listOfDomainNames: vector of Identifier;
    mmsDeletable: bool;
    reusable: bool;
    monitor: bool;
    startArgument: string;
    executionArgument: record {
      simpleString: string &optional;
      encodedString: EXTERNALt &optional;
    } &optional;
  };
  
  type FileAttributes: record {
    sizeOfFile: Unsigned32;
    lastModified: string &optional;
  };
  
  type FileOpen_Response: record {
    frsmID: Integer32;
    fileAttributes: FileAttributes;
  };
  
  type DeleteEventCondition_Response: Unsigned32;
  
  type GetEventConditionAttributes_Response: record {
    mmsDeletable: bool;
    class: EC_Class;
    prio_rity: Priority;
    severity: Unsigned8;
    alarmSummaryReports: bool;
    monitoredVariable: record {
      variableReference: VariableSpecification &optional;
      undefined: bool &optional;
    } &optional;
    evaluationInterval: Unsigned32 &optional;
  };
  
  type ReportEventConditionStatus_Response: record {
    currentState: EC_State;
    numberOfEventEnrollments: Unsigned32;
    enabled: bool &optional;
    timeOfLastTransitionToActive: EventTime &optional;
    timeOfLastTransitionToIdle: EventTime &optional;
  };
  
  type DeleteEventAction_Response: Unsigned32;
  
  type GetEventActionAttributes_Response: record {
    mmsDeletable: bool;
    listOfModifier: vector of Modifier;
  };
  
  type ReportEventActionStatus_Response: Unsigned32;
  
  type DeleteEventEnrollment_Response: Unsigned32;
  
  type AlterEventEnrollment_Response: record {
    currentState: record {
      state: EE_State &optional;
      undefined: bool &optional;
    };
    transitionTime: EventTime;
  };
  
  type ReportEventEnrollmentStatus_Response: record {
    eventConditionTransitions: Transitions;
    notificationLost: bool;
    duration: EE_Duration;
    alarmAcknowledgmentRule: AlarmAckRule &optional;
    currentState: EE_State;
  };
  
  type EventEnrollment: record {
    eventEnrollmentName: ObjectName;
    eventConditionName: record {
      eventCondition: ObjectName &optional;
      undefined: bool &optional;
    };
    eventActionName: record {
      eventAction: ObjectName &optional;
      undefined: bool &optional;
    } &optional;
    mmsDeletable: bool;
    enrollmentClass: EE_Class;
    duration: EE_Duration;
    invokeID: Unsigned32;
    remainingAcceptableDelay: Unsigned32 &optional;
  };
  
  type GetEventEnrollmentAttributes_Response: record {
    listOfEventEnrollment: vector of EventEnrollment;
    moreFollows: bool;
  };
  
  type AlarmSummary: record {
    eventConditionName: ObjectName;
    severity: Unsigned8;
    currentState: EC_State;
    unacknowledgedState: enum {
      AlarmSummary_none = 0,
      AlarmSummary_active = 1,
      AlarmSummary_idle = 2,
      both = 3,
    };
    timeOfLastTransitionToActive: EventTime &optional;
    timeOfLastTransitionToIdle: EventTime &optional;
  };
  
  type GetAlarmSummary_Response: record {
    listOfAlarmSummary: vector of AlarmSummary;
    moreFollows: bool;
  };
  
  type AlarmEnrollmentSummary: record {
    eventEnrollmentName: ObjectName;
    severity: Unsigned8;
    currentState: EC_State;
    notificationLost: bool;
    alarmAcknowledgmentRule: AlarmAckRule &optional;
    enrollementState: EE_State &optional;
    timeOfLastTransitionToActive: EventTime &optional;
    timeActiveAcknowledged: EventTime &optional;
    timeOfLastTransitionToIdle: EventTime &optional;
    timeIdleAcknowledged: EventTime &optional;
  };
  
  type GetAlarmEnrollmentSummary_Response: record {
    listOfAlarmEnrollmentSummary: vector of AlarmEnrollmentSummary;
    moreFollows: bool;
  };
  
  type JournalEntry: record {
    entryIdentifier: string;
    entryContent: EntryContent;
  };
  
  type ReadJournal_Response: record {
    listOfJournalEntry: vector of JournalEntry;
    moreFollows: bool;
  };
  
  type InitializeJournal_Response: Unsigned32;
  
  type ReportJournalStatus_Response: record {
    currentEntries: Unsigned32;
    mmsDeletable: bool;
  };
  
  type GetCapabilityList_Response: record {
    listOfCapabilities: vector of string;
    moreFollows: bool;
  };
  
  type FileRead_Response: record {
    fileData: string;
    moreFollows: bool;
  };
  
  type DirectoryEntry: record {
    filename: FileName;
    fileAttributes: FileAttributes;
  };
  
  type FileDirectory_Response: record {
    listOfDirectoryEntry: vector of DirectoryEntry;
    moreFollows: bool;
  };
  
  type ConfirmedServiceResponse: record {
    status: Status_Response &optional;
    getNameList: GetNameList_Response &optional;
    identify: Identify_Response &optional;
    _rename: Rename_Response &optional;
    read: Read_Response &optional;
    write: Write_Response &optional;
    getVariableAccessAttributes: GetVariableAccessAttributes_Response &optional;
    defineNamedVariable: DefineNamedVariable_Response &optional;
    defineScatteredAccess: DefineScatteredAccess_Response &optional;
    getScatteredAccessAttributes: GetScatteredAccessAttributes_Response &optional;
    deleteVariableAccess: DeleteVariableAccess_Response &optional;
    defineNamedVariableList: DefineNamedVariableList_Response &optional;
    getNamedVariableListAttributes: GetNamedVariableListAttributes_Response &optional;
    deleteNamedVariableList: DeleteNamedVariableList_Response &optional;
    defineNamedType: DefineNamedType_Response &optional;
    getNamedTypeAttributes: GetNamedTypeAttributes_Response &optional;
    deleteNamedType: DeleteNamedType_Response &optional;
    input: Input_Response &optional;
    _output: Output_Response &optional;
    takeControl: TakeControl_Response &optional;
    relinquishControl: RelinquishControl_Response &optional;
    defineSemaphore: DefineSemaphore_Response &optional;
    deleteSemaphore: DeleteSemaphore_Response &optional;
    reportSemaphoreStatus: ReportSemaphoreStatus_Response &optional;
    reportPoolSemaphoreStatus: ReportPoolSemaphoreStatus_Response &optional;
    reportSemaphoreEntryStatus: ReportSemaphoreEntryStatus_Response &optional;
    initiateDownloadSequence: InitiateDownloadSequence_Response &optional;
    downloadSegment: DownloadSegment_Response &optional;
    terminateDownloadSequence: TerminateDownloadSequence_Response &optional;
    initiateUploadSequence: InitiateUploadSequence_Response &optional;
    uploadSegment: UploadSegment_Response &optional;
    terminateUploadSequence: TerminateUploadSequence_Response &optional;
    requestDomainDownLoad: RequestDomainDownload_Response &optional;
    requestDomainUpload: RequestDomainUpload_Response &optional;
    loadDomainContent: LoadDomainContent_Response &optional;
    storeDomainContent: StoreDomainContent_Response &optional;
    deleteDomain: DeleteDomain_Response &optional;
    getDomainAttributes: GetDomainAttributes_Response &optional;
    createProgramInvocation: CreateProgramInvocation_Response &optional;
    deleteProgramInvocation: DeleteProgramInvocation_Response &optional;
    start: Start_Response &optional;
    stop: Stop_Response &optional;
    resume: Resume_Response &optional;
    reset: Reset_Response &optional;
    kill: Kill_Response &optional;
    getProgramInvocationAttributes: GetProgramInvocationAttributes_Response &optional;
    obtainFile: ObtainFile_Response &optional;
    fileOpen: FileOpen_Response &optional;
    defineEventCondition: DefineEventCondition_Response &optional;
    deleteEventCondition: DeleteEventCondition_Response &optional;
    getEventConditionAttributes: GetEventConditionAttributes_Response &optional;
    reportEventConditionStatus: ReportEventConditionStatus_Response &optional;
    alterEventConditionMonitoring: AlterEventConditionMonitoring_Response &optional;
    triggerEvent: TriggerEvent_Response &optional;
    defineEventAction: DefineEventAction_Response &optional;
    deleteEventAction: DeleteEventAction_Response &optional;
    getEventActionAttributes: GetEventActionAttributes_Response &optional;
    reportActionStatus: ReportEventActionStatus_Response &optional;
    defineEventEnrollment: DefineEventEnrollment_Response &optional;
    deleteEventEnrollment: DeleteEventEnrollment_Response &optional;
    alterEventEnrollment: AlterEventEnrollment_Response &optional;
    reportEventEnrollmentStatus: ReportEventEnrollmentStatus_Response &optional;
    getEventEnrollmentAttributes: GetEventEnrollmentAttributes_Response &optional;
    acknowledgeEventNotification: AcknowledgeEventNotification_Response &optional;
    getAlarmSummary: GetAlarmSummary_Response &optional;
    getAlarmEnrollmentSummary: GetAlarmEnrollmentSummary_Response &optional;
    readJournal: ReadJournal_Response &optional;
    writeJournal: WriteJournal_Response &optional;
    initializeJournal: InitializeJournal_Response &optional;
    reportJournalStatus: ReportJournalStatus_Response &optional;
    createJournal: CreateJournal_Response &optional;
    deleteJournal: DeleteJournal_Response &optional;
    getCapabilityList: GetCapabilityList_Response &optional;
    fileRead: FileRead_Response &optional;
    fileClose: FileClose_Response &optional;
    fileRename: FileRename_Response &optional;
    fileDelete: FileDelete_Response &optional;
    fileDirectory: FileDirectory_Response &optional;
  };
  
  type Confirmed_ResponsePDU: record {
    invokeID: Unsigned32;
    confirmedServiceResponse: ConfirmedServiceResponse;
    cs_request_detail: CS_Request_Detail &optional;
  };
  
  type Confirmed_ErrorPDU: record {
    invokeID: Unsigned32;
    modifierPosition: Unsigned32 &optional;
    serviceError: ServiceError;
  };
  
  type InformationReport: record {
    variableAccessSpecification: VariableAccessSpecification;
    listOfAccessResult: vector of AccessResult;
  };
  
  type UnsolicitedStatus: Status_Response;
  
  type EventNotification: record {
    eventEnrollmentName: ObjectName;
    eventConditionName: record {
      eventCondition: ObjectName &optional;
      undefined: bool &optional;
    };
    severity: Unsigned8;
    currentState: EC_State &optional;
    transitionTime: EventTime;
    notificationLost: bool;
    alarmAcknowledgmentRule: AlarmAckRule &optional;
    actionResult: record {
      eventActioName: ObjectName;
      eventActionResult: record {
        success: ConfirmedServiceResponse &optional;
        failure: ServiceError &optional;
      };
    } &optional;
  };
  
  type UnconfirmedService: record {
    informationReport: InformationReport &optional;
    unsolicitedStatus: UnsolicitedStatus &optional;
    eventNotification: EventNotification &optional;
  };
  
  type Unconfirmed_PDU: record {
    unconfirmedService: UnconfirmedService;
    cs_request_detail: CS_Request_Detail &optional;
  };
  
  type RejectPDU: record {
    originalInvokeID: Unsigned32 &optional;
    rejectReason: record {
      confirmed_requestPDU: enum {
        RejectPDU_other = 0,
        unrecognized_service = 1,
        unrecognized_modifier = 2,
        invalid_invokeID = 3,
        invalid_argument = 4,
        invalid_modifier = 5,
        max_serv_outstanding_exceeded = 6,
        max_recursion_exceeded = 8,
        value_out_of_range = 9,
      } &optional;
      confirmed_responsePDU: enum {
        RejectPDU_other = 0,
        unrecognized_service = 1,
        invalid_invokeID = 2,
        invalid_result = 3,
        max_recursion_exceeded = 5,
        value_out_of_range = 6,
      } &optional;
      confirmed_errorPDU: enum {
        RejectPDU_other = 0,
        unrecognized_service = 1,
        invalid_invokeID = 2,
        invalid_serviceError = 3,
        value_out_of_range = 4,
      } &optional;
      unconfirmedPDU: enum {
        RejectPDU_other = 0,
        unrecognized_service = 1,
        invalid_argument = 2,
        max_recursion_exceeded = 3,
        value_out_of_range = 4,
      } &optional;
      pdu_error: enum {
        unknown_pdu_type = 0,
        invalid_pdu = 1,
        illegal_acse_mapping = 2,
      } &optional;
      cancel_requestPDU: enum {
        RejectPDU_other = 0,
        invalid_invokeID = 1,
      } &optional;
      cancel_responsePDU: enum {
        RejectPDU_other = 0,
        invalid_invokeID = 1,
      } &optional;
      cancel_errorPDU: enum {
        RejectPDU_other = 0,
        invalid_invokeID = 1,
        invalid_serviceError = 2,
        value_out_of_range = 3,
      } &optional;
      conclude_requestPDU: enum {
        RejectPDU_other = 0,
        invalid_argument = 1,
      } &optional;
      conclude_responsePDU: enum {
        RejectPDU_other = 0,
        invalid_result = 1,
      } &optional;
      conclude_errorPDU: enum {
        RejectPDU_other = 0,
        invalid_serviceError = 1,
        value_out_of_range = 2,
      } &optional;
    };
  };
  
  type Cancel_RequestPDU: Unsigned32;
  
  type Cancel_ResponsePDU: Unsigned32;
  
  type Cancel_ErrorPDU: record {
    originalInvokeID: Unsigned32;
    serviceError: ServiceError;
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
    reportActionStatus,
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
  
  type Initiate_RequestPDU: record {
    localDetailCalling: Integer32 &optional;
    proposedMaxServOutstandingCalling: Integer16;
    proposedMaxServOutstandingCalled: Integer16;
    proposedDataStructureNestingLevel: Integer8 &optional;
    mmsInitRequestDetail: InitRequestDetail;
  };
  
  type InitResponseDetail: record {
    negociatedVersionNumber: Integer16;
    negociatedParameterCBB: ParameterSupportOptions;
    servicesSupportedCalled: ServiceSupportOptions;
  };
  
  type Initiate_ResponsePDU: record {
    localDetailCalled: Integer32 &optional;
    negociatedMaxServOutstandingCalling: Integer16;
    negociatedMaxServOutstandingCalled: Integer16;
    negociatedDataStructureNestingLevel: Integer8 &optional;
    mmsInitResponseDetail: InitResponseDetail;
  };
  
  type Initiate_ErrorPDU: ServiceError;
  
  type Conclude_ErrorPDU: ServiceError;
  
  type MMSpdu: record {
    confirmed_RequestPDU: Confirmed_RequestPDU &optional;
    confirmed_ResponsePDU: Confirmed_ResponsePDU &optional;
    confirmed_ErrorPDU: Confirmed_ErrorPDU &optional;
    unconfirmed_PDU: Unconfirmed_PDU &optional;
    rejectPDU: RejectPDU &optional;
    cancel_RequestPDU: Cancel_RequestPDU &optional;
    cancel_ResponsePDU: Cancel_ResponsePDU &optional;
    cancel_ErrorPDU: Cancel_ErrorPDU &optional;
    initiate_RequestPDU: Initiate_RequestPDU &optional;
    initiate_ResponsePDU: Initiate_ResponsePDU &optional;
    initiate_ErrorPDU: Initiate_ErrorPDU &optional;
    conclude_RequestPDU: Conclude_RequestPDU &optional;
    conclude_ResponsePDU: Conclude_ResponsePDU &optional;
    conclude_ErrorPDU: Conclude_ErrorPDU &optional;
  };
  
  
  # ======== SELF DEPENDENT TYPES =======
  redef record TypeSpecification += {
    typeName: ObjectName &optional;
    array: record {
      packed: bool;
      numberOfElements: Unsigned32;
      elementType: TypeSpecification;
    } &optional;
    structure: record {
      packed: bool;
      components: vector of record {
        componentName: Identifier &optional;
        componentType: TypeSpecification;
      };
    } &optional;
    boolean: bool &optional;
    bit_string: Integer32 &optional;
    integer: Unsigned8 &optional;
    unsigned: Unsigned8 &optional;
    octet_string: Integer32 &optional;
    visible_string: Integer32 &optional;
    generalized_time: bool &optional;
    binary_time: bool &optional;
    bcd: Unsigned8 &optional;
    objId: bool &optional;
  };
  
  redef record VariableSpecification += {
    name: ObjectName &optional;
    address: Address &optional;
    variableDescription: record {
      address: Address;
      typeSpecification: TypeSpecification;
    } &optional;
    scatteredAccessDescription: ScatteredAccessDescription &optional;
    invalidated: bool &optional;
  };
  
  redef record AlternateAccess += {
    unnamed: AlternateAccessSelection &optional;
    named: record {
      componentName: Identifier;
      accesst: AlternateAccessSelection;
    } &optional;
  };
  
  redef record AlternateAccessSelection += {
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
    selectAccess: record {
      component: Identifier &optional;
      index: Unsigned32 &optional;
      indexRange: record {
        lowIndex: Unsigned32;
        nmberOfElements: Unsigned32;
      } &optional;
      allElements: bool &optional;
    } &optional;
  };
  
  redef record ScatteredAccessDescription += {
    componentName: Identifier &optional;
    variableSpecification: VariableSpecification &optional;
    alternateAccess: AlternateAccess &optional;
  };
  
  redef record Data += {
    array: vector of Data &optional;
    structure: vector of Data &optional;
    boolean: bool &optional;
    bit_string: string &optional;
    integer: int &optional;
    unsigned: int &optional;
    floating_point: FloatingPoint &optional;
    octet_string: string &optional;
    visible_string: string &optional;
    binary_time: TimeOfDay &optional;
    bcd: int &optional;
    booleanArray: string &optional;
    objId: string &optional;
    mMSString: MMSString &optional;
    utc_time: UtcTime &optional;
  };
  
}
