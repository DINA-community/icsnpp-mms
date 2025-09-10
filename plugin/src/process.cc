/* THIS CODE IS GENERATED. DON'T CHANGE MANUALLY! */

#include "process.h"
#include "zeek/Val.h"

#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"

using namespace zeek;

namespace {

template <typename T> inline const T *ptr(const T *v) { return v; }

template <typename T>
inline typename std::enable_if<!std::is_pointer<T>::value, const T *>::type
ptr(const T &v) {
  return &v;
}

inline IntrusivePtr<Val> convert(const int *i) {
  return make_intrusive<IntVal>(*i);
}
inline IntrusivePtr<Val> convert(const long int *i) {
  return make_intrusive<IntVal>(*i);
}
inline IntrusivePtr<Val> convert(const unsigned int *i) {
  return make_intrusive<IntVal>(*i);
}
inline IntrusivePtr<Val> convert(const long unsigned int *i) {
  return make_intrusive<IntVal>(*i);
}

#ifdef _OBJECT_IDENTIFIER_H_
IntrusivePtr<Val> convert(const OBJECT_IDENTIFIER_t *oid) {
  std::string res;
  unsigned long arcs[100];
  int arc_slots = sizeof(arcs) / sizeof(arcs[0]);
  int count = OBJECT_IDENTIFIER_get_arcs(oid, arcs, sizeof(arcs[0]), arc_slots);
  if (count < 0 || count > arc_slots)
    return nullptr;
  for (int i = 0; i < count; i++) {
    if (i != 0)
      res += ".";
    res += std::to_string(arcs[i]);
  }
  return make_intrusive<StringVal>(res);
}
#endif

template <typename T> inline IntrusivePtr<Val> convert(const T *s) {
  return make_intrusive<StringVal>(s->size,
                                   reinterpret_cast<const char *>(s->buf));
}

bool is_bit_set(const BIT_STRING_t *s, unsigned int idx) {
  int byte_no = idx / 8;
  if (byte_no >= s->size)
    return false;
  auto byte = s->buf[byte_no];
  return byte & (1 << (idx % 8));
}

/*
 * In the event of an error, the function does not return,
 * but deliberately causes a core dump.
 */
template <typename T>
IntrusivePtr<T> get_field_type(IntrusivePtr<RecordVal> container,
                               const char *fieldname) {
  auto tag = TYPE_RECORD;
  if constexpr (std::is_same_v<T, VectorType>)
    tag = TYPE_VECTOR;
  auto container_type = cast_intrusive<RecordType>(container->GetType());
  if (!container_type->HasField(fieldname)) {
    reporter->InternalError("Unable to process '%s': Missing field '%s'",
                            container_type->GetName().c_str(), fieldname);
  }
  auto field_type = container_type->GetFieldType(fieldname);
  if (field_type->Tag() != tag) {
    reporter->InternalError(
        "Unable to process '%s': Field '%s' is of wrong type",
        container_type->GetName().c_str(), fieldname);
  }
  return cast_intrusive<T>(field_type);
}

template <typename T>
IntrusivePtr<T> get_field_type(IntrusivePtr<VectorVal> container) {
  auto tag = TYPE_RECORD;
  if constexpr (std::is_same_v<T, VectorType>)
    tag = TYPE_VECTOR;
  auto subtype = container->GetType()->Yield();
  if (!subtype || subtype->Tag() != tag) {
    reporter->InternalError("Unable to process '%s': Content is of wrong type",
                            container->GetType()->GetName().c_str());
  }
  return cast_intrusive<T>(subtype);
}
} // namespace

namespace zeek::plugin::mms {

IntrusivePtr<Val> process_ReportedOptFlds(const ReportedOptFlds_t *src) {
  static const auto type = id::find_type<VectorType>("mms::ReportedOptFlds");
  static IntrusivePtr<EnumType> enum_type = nullptr;
  if (!enum_type) {
    auto subtype = type->Yield();
    if (!subtype || subtype->Tag() != TYPE_ENUM)
      reporter->InternalError("Unable to process 'ReportedOptFlds': "
                              "%s is not a vector of enums",
                              type->GetName().c_str());
    enum_type = cast_intrusive<EnumType>(subtype);
  }
  auto res = make_intrusive<VectorVal>(type);
  if (src ? is_bit_set(src, 0) : false) /* reserved */
    res->Append(enum_type->GetEnumVal(0));
  if (src ? is_bit_set(src, 1) : false) /* sequence-number */
    res->Append(enum_type->GetEnumVal(1));
  if (src ? is_bit_set(src, 2) : false) /* report-time-stamp */
    res->Append(enum_type->GetEnumVal(2));
  if (src ? is_bit_set(src, 3) : false) /* reason-for-inclusion */
    res->Append(enum_type->GetEnumVal(3));
  if (src ? is_bit_set(src, 4) : false) /* data-set-name */
    res->Append(enum_type->GetEnumVal(4));
  if (src ? is_bit_set(src, 5) : false) /* data-reference */
    res->Append(enum_type->GetEnumVal(5));
  if (src ? is_bit_set(src, 6) : false) /* buffer-overflow */
    res->Append(enum_type->GetEnumVal(6));
  if (src ? is_bit_set(src, 7) : false) /* entryID */
    res->Append(enum_type->GetEnumVal(7));
  if (src ? is_bit_set(src, 8) : false) /* conf-revision */
    res->Append(enum_type->GetEnumVal(8));
  if (src ? is_bit_set(src, 9) : false) /* segmentation */
    res->Append(enum_type->GetEnumVal(9));
  return res;
}

IntrusivePtr<Val> process_MMSpdu(const MMSpdu_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::MMSpdu");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == MMSpdu_PR_confirmed_RequestPDU) {
      const auto _new_src = ptr(src->choice.confirmed_RequestPDU);
      const auto src = _new_src;
      const auto res = process_Confirmed_RequestPDU(src);
      container->AssignField("confirmed_RequestPDU", res);
    }

    if (src->present == MMSpdu_PR_confirmed_ResponsePDU) {
      const auto _new_src = ptr(src->choice.confirmed_ResponsePDU);
      const auto src = _new_src;
      const auto res = process_Confirmed_ResponsePDU(src);
      container->AssignField("confirmed_ResponsePDU", res);
    }

    if (src->present == MMSpdu_PR_confirmed_ErrorPDU) {
      const auto _new_src = ptr(src->choice.confirmed_ErrorPDU);
      const auto src = _new_src;
      const auto res = process_Confirmed_ErrorPDU(src);
      container->AssignField("confirmed_ErrorPDU", res);
    }

    if (src->present == MMSpdu_PR_unconfirmed_PDU) {
      const auto _new_src = ptr(src->choice.unconfirmed_PDU);
      const auto src = _new_src;
      const auto res = process_Unconfirmed_PDU(src);
      container->AssignField("unconfirmed_PDU", res);
    }

    if (src->present == MMSpdu_PR_rejectPDU) {
      const auto _new_src = ptr(src->choice.rejectPDU);
      const auto src = _new_src;
      const auto res = process_RejectPDU(src);
      container->AssignField("rejectPDU", res);
    }

    if (src->present == MMSpdu_PR_cancel_RequestPDU) {
      const auto _new_src = ptr(src->choice.cancel_RequestPDU);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("cancel_RequestPDU", res);
    }

    if (src->present == MMSpdu_PR_cancel_ResponsePDU) {
      const auto _new_src = ptr(src->choice.cancel_ResponsePDU);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("cancel_ResponsePDU", res);
    }

    if (src->present == MMSpdu_PR_cancel_ErrorPDU) {
      const auto _new_src = ptr(src->choice.cancel_ErrorPDU);
      const auto src = _new_src;
      const auto res = process_Cancel_ErrorPDU(src);
      container->AssignField("cancel_ErrorPDU", res);
    }

    if (src->present == MMSpdu_PR_initiate_RequestPDU) {
      const auto _new_src = ptr(src->choice.initiate_RequestPDU);
      const auto src = _new_src;
      const auto res = process_Initiate_RequestPDU(src);
      container->AssignField("initiate_RequestPDU", res);
    }

    if (src->present == MMSpdu_PR_initiate_ResponsePDU) {
      const auto _new_src = ptr(src->choice.initiate_ResponsePDU);
      const auto src = _new_src;
      const auto res = process_Initiate_ResponsePDU(src);
      container->AssignField("initiate_ResponsePDU", res);
    }

    if (src->present == MMSpdu_PR_initiate_ErrorPDU) {
      const auto _new_src = ptr(src->choice.initiate_ErrorPDU);
      const auto src = _new_src;
      const auto res = process_ServiceError(src);
      container->AssignField("initiate_ErrorPDU", res);
    }

    if (src->present == MMSpdu_PR_conclude_RequestPDU) {
      const auto _new_src = ptr(src->choice.conclude_RequestPDU);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("conclude_RequestPDU", res);
    }

    if (src->present == MMSpdu_PR_conclude_ResponsePDU) {
      const auto _new_src = ptr(src->choice.conclude_ResponsePDU);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("conclude_ResponsePDU", res);
    }

    if (src->present == MMSpdu_PR_conclude_ErrorPDU) {
      const auto _new_src = ptr(src->choice.conclude_ErrorPDU);
      const auto src = _new_src;
      const auto res = process_ServiceError(src);
      container->AssignField("conclude_ErrorPDU", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_Confirmed_RequestPDU(const Confirmed_RequestPDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::Confirmed_RequestPDU");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->invokeID);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("invokeID", res);
    }

    if (src->listOfModifier) {
      const auto _new_src = ptr(src->listOfModifier);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfModifier");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_Modifier(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfModifier", res);
    }

    {
      const auto _new_src = ptr(src->confirmedServiceRequest);
      const auto src = _new_src;
      const auto res = process_ConfirmedServiceRequest(src);
      container->AssignField("confirmedServiceRequest", res);
    }

    if (src->cs_request_detail) {
      const auto _new_src = ptr(src->cs_request_detail);
      const auto src = _new_src;
      const auto res = process_CS_Request_Detail(src);
      container->AssignField("cs_request_detail", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Unconfirmed_PDU(const Unconfirmed_PDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Unconfirmed_PDU");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->unconfirmedService);
      const auto src = _new_src;
      const auto res = process_UnconfirmedService(src);
      container->AssignField("unconfirmedService", res);
    }

    if (src->cs_request_detail) {
      const auto _new_src = ptr(src->cs_request_detail);
      const auto src = _new_src;
      const auto res = process_CS_Request_Detail(src);
      container->AssignField("cs_request_detail", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_Confirmed_ResponsePDU(const Confirmed_ResponsePDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::Confirmed_ResponsePDU");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->invokeID);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("invokeID", res);
    }

    {
      const auto _new_src = ptr(src->confirmedServiceResponse);
      const auto src = _new_src;
      const auto res = process_ConfirmedServiceResponse(src);
      container->AssignField("confirmedServiceResponse", res);
    }

    if (src->cs_request_detail) {
      const auto _new_src = ptr(src->cs_request_detail);
      const auto src = _new_src;
      const auto res = process_CS_Request_Detail(src);
      container->AssignField("cs_request_detail", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Confirmed_ErrorPDU(const Confirmed_ErrorPDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::Confirmed_ErrorPDU");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->invokeID);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("invokeID", res);
    }

    if (src->modifierPosition) {
      const auto _new_src = ptr(src->modifierPosition);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("modifierPosition", res);
    }

    {
      const auto _new_src = ptr(src->serviceError);
      const auto src = _new_src;
      const auto res = process_ServiceError(src);
      container->AssignField("serviceError", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_UnconfirmedService(const UnconfirmedService_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::UnconfirmedService");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == UnconfirmedService_PR_informationReport) {
      const auto _new_src = ptr(src->choice.informationReport);
      const auto src = _new_src;
      const auto res = process_InformationReport(src);
      container->AssignField("informationReport", res);
    }

    if (src->present == UnconfirmedService_PR_unsolicitedStatus) {
      const auto _new_src = ptr(src->choice.unsolicitedStatus);
      const auto src = _new_src;
      const auto res = process_Status_Response(src);
      container->AssignField("unsolicitedStatus", res);
    }

    if (src->present == UnconfirmedService_PR_eventNotification) {
      const auto _new_src = ptr(src->choice.eventNotification);
      const auto src = _new_src;
      const auto res = process_EventNotification(src);
      container->AssignField("eventNotification", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Modifier(const Modifier_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Modifier");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == Modifier_PR_attach_To_Event_Condition) {
      const auto _new_src = ptr(src->choice.attach_To_Event_Condition);
      const auto src = _new_src;
      const auto res = process_AttachToEventCondition(src);
      container->AssignField("attach_To_Event_Condition", res);
    }

    if (src->present == Modifier_PR_attach_To_Semaphore) {
      const auto _new_src = ptr(src->choice.attach_To_Semaphore);
      const auto src = _new_src;
      const auto res = process_AttachToSemaphore(src);
      container->AssignField("attach_To_Semaphore", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_ConfirmedServiceRequest(const ConfirmedServiceRequest_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ConfirmedServiceRequest");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == ConfirmedServiceRequest_PR_status) {
      const auto _new_src = ptr(src->choice.status);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("status", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_getNameList) {
      const auto _new_src = ptr(src->choice.getNameList);
      const auto src = _new_src;
      const auto res = process_GetNameList_Request(src);
      container->AssignField("getNameList", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_identify) {
      const auto _new_src = ptr(src->choice.identify);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("identify", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_rename) {
      const auto _new_src = ptr(src->choice.rename);
      const auto src = _new_src;
      const auto res = process_Rename_Request(src);
      container->AssignField("_rename", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_read) {
      const auto _new_src = ptr(src->choice.read);
      const auto src = _new_src;
      const auto res = process_Read_Request(src);
      container->AssignField("read", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_write) {
      const auto _new_src = ptr(src->choice.write);
      const auto src = _new_src;
      const auto res = process_Write_Request(src);
      container->AssignField("write", res);
    }

    if (src->present ==
        ConfirmedServiceRequest_PR_getVariableAccessAttributes) {
      const auto _new_src = ptr(src->choice.getVariableAccessAttributes);
      const auto src = _new_src;
      const auto res = process_GetVariableAccessAttributes_Request(src);
      container->AssignField("getVariableAccessAttributes", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_defineNamedVariable) {
      const auto _new_src = ptr(src->choice.defineNamedVariable);
      const auto src = _new_src;
      const auto res = process_DefineNamedVariable_Request(src);
      container->AssignField("defineNamedVariable", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_defineScatteredAccess) {
      const auto _new_src = ptr(src->choice.defineScatteredAccess);
      const auto src = _new_src;
      const auto res = process_DefineScatteredAccess_Request(src);
      container->AssignField("defineScatteredAccess", res);
    }

    if (src->present ==
        ConfirmedServiceRequest_PR_getScatteredAccessAttributes) {
      const auto _new_src = ptr(src->choice.getScatteredAccessAttributes);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("getScatteredAccessAttributes", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_deleteVariableAccess) {
      const auto _new_src = ptr(src->choice.deleteVariableAccess);
      const auto src = _new_src;
      const auto res = process_DeleteVariableAccess_Request(src);
      container->AssignField("deleteVariableAccess", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_defineNamedVariableList) {
      const auto _new_src = ptr(src->choice.defineNamedVariableList);
      const auto src = _new_src;
      const auto res = process_DefineNamedVariableList_Request(src);
      container->AssignField("defineNamedVariableList", res);
    }

    if (src->present ==
        ConfirmedServiceRequest_PR_getNamedVariableListAttributes) {
      const auto _new_src = ptr(src->choice.getNamedVariableListAttributes);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("getNamedVariableListAttributes", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_deleteNamedVariableList) {
      const auto _new_src = ptr(src->choice.deleteNamedVariableList);
      const auto src = _new_src;
      const auto res = process_DeleteNamedVariableList_Request(src);
      container->AssignField("deleteNamedVariableList", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_defineNamedType) {
      const auto _new_src = ptr(src->choice.defineNamedType);
      const auto src = _new_src;
      const auto res = process_DefineNamedType_Request(src);
      container->AssignField("defineNamedType", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_getNamedTypeAttributes) {
      const auto _new_src = ptr(src->choice.getNamedTypeAttributes);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("getNamedTypeAttributes", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_deleteNamedType) {
      const auto _new_src = ptr(src->choice.deleteNamedType);
      const auto src = _new_src;
      const auto res = process_DeleteNamedType_Request(src);
      container->AssignField("deleteNamedType", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_input) {
      const auto _new_src = ptr(src->choice.input);
      const auto src = _new_src;
      const auto res = process_Input_Request(src);
      container->AssignField("input", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_output) {
      const auto _new_src = ptr(src->choice.output);
      const auto src = _new_src;
      const auto res = process_Output_Request(src);
      container->AssignField("_output", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_takeControl) {
      const auto _new_src = ptr(src->choice.takeControl);
      const auto src = _new_src;
      const auto res = process_TakeControl_Request(src);
      container->AssignField("takeControl", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_relinquishControl) {
      const auto _new_src = ptr(src->choice.relinquishControl);
      const auto src = _new_src;
      const auto res = process_RelinquishControl_Request(src);
      container->AssignField("relinquishControl", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_defineSemaphore) {
      const auto _new_src = ptr(src->choice.defineSemaphore);
      const auto src = _new_src;
      const auto res = process_DefineSemaphore_Request(src);
      container->AssignField("defineSemaphore", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_deleteSemaphore) {
      const auto _new_src = ptr(src->choice.deleteSemaphore);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("deleteSemaphore", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_reportSemaphoreStatus) {
      const auto _new_src = ptr(src->choice.reportSemaphoreStatus);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("reportSemaphoreStatus", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_reportPoolSemaphoreStatus) {
      const auto _new_src = ptr(src->choice.reportPoolSemaphoreStatus);
      const auto src = _new_src;
      const auto res = process_ReportPoolSemaphoreStatus_Request(src);
      container->AssignField("reportPoolSemaphoreStatus", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_reportSemaphoreEntryStatus) {
      const auto _new_src = ptr(src->choice.reportSemaphoreEntryStatus);
      const auto src = _new_src;
      const auto res = process_ReportSemaphoreEntryStatus_Request(src);
      container->AssignField("reportSemaphoreEntryStatus", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_initiateDownloadSequence) {
      const auto _new_src = ptr(src->choice.initiateDownloadSequence);
      const auto src = _new_src;
      const auto res = process_InitiateDownloadSequence_Request(src);
      container->AssignField("initiateDownloadSequence", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_downloadSegment) {
      const auto _new_src = ptr(src->choice.downloadSegment);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("downloadSegment", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_terminateDownloadSequence) {
      const auto _new_src = ptr(src->choice.terminateDownloadSequence);
      const auto src = _new_src;
      const auto res = process_TerminateDownloadSequence_Request(src);
      container->AssignField("terminateDownloadSequence", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_initiateUploadSequence) {
      const auto _new_src = ptr(src->choice.initiateUploadSequence);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("initiateUploadSequence", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_uploadSegment) {
      const auto _new_src = ptr(src->choice.uploadSegment);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("uploadSegment", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_terminateUploadSequence) {
      const auto _new_src = ptr(src->choice.terminateUploadSequence);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("terminateUploadSequence", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_requestDomainDownload) {
      const auto _new_src = ptr(src->choice.requestDomainDownload);
      const auto src = _new_src;
      const auto res = process_RequestDomainDownload_Request(src);
      container->AssignField("requestDomainDownload", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_requestDomainUpload) {
      const auto _new_src = ptr(src->choice.requestDomainUpload);
      const auto src = _new_src;
      const auto res = process_RequestDomainUpload_Request(src);
      container->AssignField("requestDomainUpload", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_loadDomainContent) {
      const auto _new_src = ptr(src->choice.loadDomainContent);
      const auto src = _new_src;
      const auto res = process_LoadDomainContent_Request(src);
      container->AssignField("loadDomainContent", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_storeDomainContent) {
      const auto _new_src = ptr(src->choice.storeDomainContent);
      const auto src = _new_src;
      const auto res = process_StoreDomainContent_Request(src);
      container->AssignField("storeDomainContent", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_deleteDomain) {
      const auto _new_src = ptr(src->choice.deleteDomain);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("deleteDomain", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_getDomainAttributes) {
      const auto _new_src = ptr(src->choice.getDomainAttributes);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("getDomainAttributes", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_createProgramInvocation) {
      const auto _new_src = ptr(src->choice.createProgramInvocation);
      const auto src = _new_src;
      const auto res = process_CreateProgramInvocation_Request(src);
      container->AssignField("createProgramInvocation", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_deleteProgramInvocation) {
      const auto _new_src = ptr(src->choice.deleteProgramInvocation);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("deleteProgramInvocation", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_start) {
      const auto _new_src = ptr(src->choice.start);
      const auto src = _new_src;
      const auto res = process_Start_Request(src);
      container->AssignField("start", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_stop) {
      const auto _new_src = ptr(src->choice.stop);
      const auto src = _new_src;
      const auto res = process_Stop_Request(src);
      container->AssignField("stop", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_resume) {
      const auto _new_src = ptr(src->choice.resume);
      const auto src = _new_src;
      const auto res = process_Resume_Request(src);
      container->AssignField("resume", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_reset) {
      const auto _new_src = ptr(src->choice.reset);
      const auto src = _new_src;
      const auto res = process_Reset_Request(src);
      container->AssignField("reset", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_kill) {
      const auto _new_src = ptr(src->choice.kill);
      const auto src = _new_src;
      const auto res = process_Kill_Request(src);
      container->AssignField("kill", res);
    }

    if (src->present ==
        ConfirmedServiceRequest_PR_getProgramInvocationAttributes) {
      const auto _new_src = ptr(src->choice.getProgramInvocationAttributes);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("getProgramInvocationAttributes", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_obtainFile) {
      const auto _new_src = ptr(src->choice.obtainFile);
      const auto src = _new_src;
      const auto res = process_ObtainFile_Request(src);
      container->AssignField("obtainFile", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_defineEventCondition) {
      const auto _new_src = ptr(src->choice.defineEventCondition);
      const auto src = _new_src;
      const auto res = process_DefineEventCondition_Request(src);
      container->AssignField("defineEventCondition", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_deleteEventCondition) {
      const auto _new_src = ptr(src->choice.deleteEventCondition);
      const auto src = _new_src;
      const auto res = process_DeleteEventCondition_Request(src);
      container->AssignField("deleteEventCondition", res);
    }

    if (src->present ==
        ConfirmedServiceRequest_PR_getEventConditionAttributes) {
      const auto _new_src = ptr(src->choice.getEventConditionAttributes);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("getEventConditionAttributes", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_reportEventConditionStatus) {
      const auto _new_src = ptr(src->choice.reportEventConditionStatus);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("reportEventConditionStatus", res);
    }

    if (src->present ==
        ConfirmedServiceRequest_PR_alterEventConditionMonitoring) {
      const auto _new_src = ptr(src->choice.alterEventConditionMonitoring);
      const auto src = _new_src;
      const auto res = process_AlterEventConditionMonitoring_Request(src);
      container->AssignField("alterEventConditionMonitoring", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_triggerEvent) {
      const auto _new_src = ptr(src->choice.triggerEvent);
      const auto src = _new_src;
      const auto res = process_TriggerEvent_Request(src);
      container->AssignField("triggerEvent", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_defineEventAction) {
      const auto _new_src = ptr(src->choice.defineEventAction);
      const auto src = _new_src;
      const auto res = process_DefineEventAction_Request(src);
      container->AssignField("defineEventAction", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_deleteEventAction) {
      const auto _new_src = ptr(src->choice.deleteEventAction);
      const auto src = _new_src;
      const auto res = process_DeleteEventAction_Request(src);
      container->AssignField("deleteEventAction", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_getEventActionAttributes) {
      const auto _new_src = ptr(src->choice.getEventActionAttributes);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("getEventActionAttributes", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_reportEventActionStatus) {
      const auto _new_src = ptr(src->choice.reportEventActionStatus);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("reportEventActionStatus", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_defineEventEnrollment) {
      const auto _new_src = ptr(src->choice.defineEventEnrollment);
      const auto src = _new_src;
      const auto res = process_DefineEventEnrollment_Request(src);
      container->AssignField("defineEventEnrollment", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_deleteEventEnrollment) {
      const auto _new_src = ptr(src->choice.deleteEventEnrollment);
      const auto src = _new_src;
      const auto res = process_DeleteEventEnrollment_Request(src);
      container->AssignField("deleteEventEnrollment", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_alterEventEnrollment) {
      const auto _new_src = ptr(src->choice.alterEventEnrollment);
      const auto src = _new_src;
      const auto res = process_AlterEventEnrollment_Request(src);
      container->AssignField("alterEventEnrollment", res);
    }

    if (src->present ==
        ConfirmedServiceRequest_PR_reportEventEnrollmentStatus) {
      const auto _new_src = ptr(src->choice.reportEventEnrollmentStatus);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("reportEventEnrollmentStatus", res);
    }

    if (src->present ==
        ConfirmedServiceRequest_PR_getEventEnrollmentAttributes) {
      const auto _new_src = ptr(src->choice.getEventEnrollmentAttributes);
      const auto src = _new_src;
      const auto res = process_GetEventEnrollmentAttributes_Request(src);
      container->AssignField("getEventEnrollmentAttributes", res);
    }

    if (src->present ==
        ConfirmedServiceRequest_PR_acknowledgeEventNotification) {
      const auto _new_src = ptr(src->choice.acknowledgeEventNotification);
      const auto src = _new_src;
      const auto res = process_AcknowledgeEventNotification_Request(src);
      container->AssignField("acknowledgeEventNotification", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_getAlarmSummary) {
      const auto _new_src = ptr(src->choice.getAlarmSummary);
      const auto src = _new_src;
      const auto res = process_GetAlarmSummary_Request(src);
      container->AssignField("getAlarmSummary", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_getAlarmEnrollmentSummary) {
      const auto _new_src = ptr(src->choice.getAlarmEnrollmentSummary);
      const auto src = _new_src;
      const auto res = process_GetAlarmEnrollmentSummary_Request(src);
      container->AssignField("getAlarmEnrollmentSummary", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_readJournal) {
      const auto _new_src = ptr(src->choice.readJournal);
      const auto src = _new_src;
      const auto res = process_ReadJournal_Request(src);
      container->AssignField("readJournal", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_writeJournal) {
      const auto _new_src = ptr(src->choice.writeJournal);
      const auto src = _new_src;
      const auto res = process_WriteJournal_Request(src);
      container->AssignField("writeJournal", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_initializeJournal) {
      const auto _new_src = ptr(src->choice.initializeJournal);
      const auto src = _new_src;
      const auto res = process_InitializeJournal_Request(src);
      container->AssignField("initializeJournal", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_reportJournalStatus) {
      const auto _new_src = ptr(src->choice.reportJournalStatus);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("reportJournalStatus", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_createJournal) {
      const auto _new_src = ptr(src->choice.createJournal);
      const auto src = _new_src;
      const auto res = process_CreateJournal_Request(src);
      container->AssignField("createJournal", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_deleteJournal) {
      const auto _new_src = ptr(src->choice.deleteJournal);
      const auto src = _new_src;
      const auto res = process_DeleteJournal_Request(src);
      container->AssignField("deleteJournal", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_getCapabilityList) {
      const auto _new_src = ptr(src->choice.getCapabilityList);
      const auto src = _new_src;
      const auto res = process_GetCapabilityList_Request(src);
      container->AssignField("getCapabilityList", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_fileOpen) {
      const auto _new_src = ptr(src->choice.fileOpen);
      const auto src = _new_src;
      const auto res = process_FileOpen_Request(src);
      container->AssignField("fileOpen", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_fileRead) {
      const auto _new_src = ptr(src->choice.fileRead);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("fileRead", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_fileClose) {
      const auto _new_src = ptr(src->choice.fileClose);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("fileClose", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_fileRename) {
      const auto _new_src = ptr(src->choice.fileRename);
      const auto src = _new_src;
      const auto res = process_FileRename_Request(src);
      container->AssignField("fileRename", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_fileDelete) {
      const auto _new_src = ptr(src->choice.fileDelete);
      const auto src = _new_src;
      const auto res = process_FileName(src);
      container->AssignField("fileDelete", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_fileDirectory) {
      const auto _new_src = ptr(src->choice.fileDirectory);
      const auto src = _new_src;
      const auto res = process_FileDirectory_Request(src);
      container->AssignField("fileDirectory", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_CS_Request_Detail(const CS_Request_Detail_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::CS_Request_Detail");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == CS_Request_Detail_PR_foo) {
      const auto _new_src = ptr(src->choice.foo);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("foo", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_ConfirmedServiceResponse(const ConfirmedServiceResponse_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ConfirmedServiceResponse");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == ConfirmedServiceResponse_PR_status) {
      const auto _new_src = ptr(src->choice.status);
      const auto src = _new_src;
      const auto res = process_Status_Response(src);
      container->AssignField("status", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_getNameList) {
      const auto _new_src = ptr(src->choice.getNameList);
      const auto src = _new_src;
      const auto res = process_GetNameList_Response(src);
      container->AssignField("getNameList", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_identify) {
      const auto _new_src = ptr(src->choice.identify);
      const auto src = _new_src;
      const auto res = process_Identify_Response(src);
      container->AssignField("identify", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_rename) {
      const auto _new_src = ptr(src->choice.rename);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("_rename", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_read) {
      const auto _new_src = ptr(src->choice.read);
      const auto src = _new_src;
      const auto res = process_Read_Response(src);
      container->AssignField("read", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_write) {
      const auto _new_src = ptr(src->choice.write);
      const auto src = _new_src;
      const auto res = process_Write_Response(src);
      container->AssignField("write", res);
    }

    if (src->present ==
        ConfirmedServiceResponse_PR_getVariableAccessAttributes) {
      const auto _new_src = ptr(src->choice.getVariableAccessAttributes);
      const auto src = _new_src;
      const auto res = process_GetVariableAccessAttributes_Response(src);
      container->AssignField("getVariableAccessAttributes", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_defineNamedVariable) {
      const auto _new_src = ptr(src->choice.defineNamedVariable);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("defineNamedVariable", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_defineScatteredAccess) {
      const auto _new_src = ptr(src->choice.defineScatteredAccess);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("defineScatteredAccess", res);
    }

    if (src->present ==
        ConfirmedServiceResponse_PR_getScatteredAccessAttributes) {
      const auto _new_src = ptr(src->choice.getScatteredAccessAttributes);
      const auto src = _new_src;
      const auto res = process_GetScatteredAccessAttributes_Response(src);
      container->AssignField("getScatteredAccessAttributes", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_deleteVariableAccess) {
      const auto _new_src = ptr(src->choice.deleteVariableAccess);
      const auto src = _new_src;
      const auto res = process_DeleteVariableAccess_Response(src);
      container->AssignField("deleteVariableAccess", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_defineNamedVariableList) {
      const auto _new_src = ptr(src->choice.defineNamedVariableList);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("defineNamedVariableList", res);
    }

    if (src->present ==
        ConfirmedServiceResponse_PR_getNamedVariableListAttributes) {
      const auto _new_src = ptr(src->choice.getNamedVariableListAttributes);
      const auto src = _new_src;
      const auto res = process_GetNamedVariableListAttributes_Response(src);
      container->AssignField("getNamedVariableListAttributes", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_deleteNamedVariableList) {
      const auto _new_src = ptr(src->choice.deleteNamedVariableList);
      const auto src = _new_src;
      const auto res = process_DeleteNamedVariableList_Response(src);
      container->AssignField("deleteNamedVariableList", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_defineNamedType) {
      const auto _new_src = ptr(src->choice.defineNamedType);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("defineNamedType", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_getNamedTypeAttributes) {
      const auto _new_src = ptr(src->choice.getNamedTypeAttributes);
      const auto src = _new_src;
      const auto res = process_GetNamedTypeAttributes_Response(src);
      container->AssignField("getNamedTypeAttributes", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_deleteNamedType) {
      const auto _new_src = ptr(src->choice.deleteNamedType);
      const auto src = _new_src;
      const auto res = process_DeleteNamedType_Response(src);
      container->AssignField("deleteNamedType", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_input) {
      const auto _new_src = ptr(src->choice.input);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("input", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_output) {
      const auto _new_src = ptr(src->choice.output);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("_output", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_takeControl) {
      const auto _new_src = ptr(src->choice.takeControl);
      const auto src = _new_src;
      const auto res = process_TakeControl_Response(src);
      container->AssignField("takeControl", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_relinquishControl) {
      const auto _new_src = ptr(src->choice.relinquishControl);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("relinquishControl", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_defineSemaphore) {
      const auto _new_src = ptr(src->choice.defineSemaphore);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("defineSemaphore", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_deleteSemaphore) {
      const auto _new_src = ptr(src->choice.deleteSemaphore);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("deleteSemaphore", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_reportSemaphoreStatus) {
      const auto _new_src = ptr(src->choice.reportSemaphoreStatus);
      const auto src = _new_src;
      const auto res = process_ReportSemaphoreStatus_Response(src);
      container->AssignField("reportSemaphoreStatus", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_reportPoolSemaphoreStatus) {
      const auto _new_src = ptr(src->choice.reportPoolSemaphoreStatus);
      const auto src = _new_src;
      const auto res = process_ReportPoolSemaphoreStatus_Response(src);
      container->AssignField("reportPoolSemaphoreStatus", res);
    }

    if (src->present ==
        ConfirmedServiceResponse_PR_reportSemaphoreEntryStatus) {
      const auto _new_src = ptr(src->choice.reportSemaphoreEntryStatus);
      const auto src = _new_src;
      const auto res = process_ReportSemaphoreEntryStatus_Response(src);
      container->AssignField("reportSemaphoreEntryStatus", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_initiateDownloadSequence) {
      const auto _new_src = ptr(src->choice.initiateDownloadSequence);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("initiateDownloadSequence", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_downloadSegment) {
      const auto _new_src = ptr(src->choice.downloadSegment);
      const auto src = _new_src;
      const auto res = process_DownloadSegment_Response(src);
      container->AssignField("downloadSegment", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_terminateDownloadSequence) {
      const auto _new_src = ptr(src->choice.terminateDownloadSequence);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("terminateDownloadSequence", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_initiateUploadSequence) {
      const auto _new_src = ptr(src->choice.initiateUploadSequence);
      const auto src = _new_src;
      const auto res = process_InitiateUploadSequence_Response(src);
      container->AssignField("initiateUploadSequence", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_uploadSegment) {
      const auto _new_src = ptr(src->choice.uploadSegment);
      const auto src = _new_src;
      const auto res = process_UploadSegment_Response(src);
      container->AssignField("uploadSegment", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_terminateUploadSequence) {
      const auto _new_src = ptr(src->choice.terminateUploadSequence);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("terminateUploadSequence", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_requestDomainDownLoad) {
      const auto _new_src = ptr(src->choice.requestDomainDownLoad);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("requestDomainDownLoad", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_requestDomainUpload) {
      const auto _new_src = ptr(src->choice.requestDomainUpload);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("requestDomainUpload", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_loadDomainContent) {
      const auto _new_src = ptr(src->choice.loadDomainContent);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("loadDomainContent", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_storeDomainContent) {
      const auto _new_src = ptr(src->choice.storeDomainContent);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("storeDomainContent", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_deleteDomain) {
      const auto _new_src = ptr(src->choice.deleteDomain);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("deleteDomain", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_getDomainAttributes) {
      const auto _new_src = ptr(src->choice.getDomainAttributes);
      const auto src = _new_src;
      const auto res = process_GetDomainAttributes_Response(src);
      container->AssignField("getDomainAttributes", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_createProgramInvocation) {
      const auto _new_src = ptr(src->choice.createProgramInvocation);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("createProgramInvocation", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_deleteProgramInvocation) {
      const auto _new_src = ptr(src->choice.deleteProgramInvocation);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("deleteProgramInvocation", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_start) {
      const auto _new_src = ptr(src->choice.start);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("start", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_stop) {
      const auto _new_src = ptr(src->choice.stop);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("stop", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_resume) {
      const auto _new_src = ptr(src->choice.resume);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("resume", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_reset) {
      const auto _new_src = ptr(src->choice.reset);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("reset", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_kill) {
      const auto _new_src = ptr(src->choice.kill);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("kill", res);
    }

    if (src->present ==
        ConfirmedServiceResponse_PR_getProgramInvocationAttributes) {
      const auto _new_src = ptr(src->choice.getProgramInvocationAttributes);
      const auto src = _new_src;
      const auto res = process_GetProgramInvocationAttributes_Response(src);
      container->AssignField("getProgramInvocationAttributes", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_obtainFile) {
      const auto _new_src = ptr(src->choice.obtainFile);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("obtainFile", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_fileOpen) {
      const auto _new_src = ptr(src->choice.fileOpen);
      const auto src = _new_src;
      const auto res = process_FileOpen_Response(src);
      container->AssignField("fileOpen", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_defineEventCondition) {
      const auto _new_src = ptr(src->choice.defineEventCondition);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("defineEventCondition", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_deleteEventCondition) {
      const auto _new_src = ptr(src->choice.deleteEventCondition);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("deleteEventCondition", res);
    }

    if (src->present ==
        ConfirmedServiceResponse_PR_getEventConditionAttributes) {
      const auto _new_src = ptr(src->choice.getEventConditionAttributes);
      const auto src = _new_src;
      const auto res = process_GetEventConditionAttributes_Response(src);
      container->AssignField("getEventConditionAttributes", res);
    }

    if (src->present ==
        ConfirmedServiceResponse_PR_reportEventConditionStatus) {
      const auto _new_src = ptr(src->choice.reportEventConditionStatus);
      const auto src = _new_src;
      const auto res = process_ReportEventConditionStatus_Response(src);
      container->AssignField("reportEventConditionStatus", res);
    }

    if (src->present ==
        ConfirmedServiceResponse_PR_alterEventConditionMonitoring) {
      const auto _new_src = ptr(src->choice.alterEventConditionMonitoring);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("alterEventConditionMonitoring", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_triggerEvent) {
      const auto _new_src = ptr(src->choice.triggerEvent);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("triggerEvent", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_defineEventAction) {
      const auto _new_src = ptr(src->choice.defineEventAction);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("defineEventAction", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_deleteEventAction) {
      const auto _new_src = ptr(src->choice.deleteEventAction);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("deleteEventAction", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_getEventActionAttributes) {
      const auto _new_src = ptr(src->choice.getEventActionAttributes);
      const auto src = _new_src;
      const auto res = process_GetEventActionAttributes_Response(src);
      container->AssignField("getEventActionAttributes", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_reportActionStatus) {
      const auto _new_src = ptr(src->choice.reportActionStatus);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("reportActionStatus", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_defineEventEnrollment) {
      const auto _new_src = ptr(src->choice.defineEventEnrollment);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("defineEventEnrollment", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_deleteEventEnrollment) {
      const auto _new_src = ptr(src->choice.deleteEventEnrollment);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("deleteEventEnrollment", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_alterEventEnrollment) {
      const auto _new_src = ptr(src->choice.alterEventEnrollment);
      const auto src = _new_src;
      const auto res = process_AlterEventEnrollment_Response(src);
      container->AssignField("alterEventEnrollment", res);
    }

    if (src->present ==
        ConfirmedServiceResponse_PR_reportEventEnrollmentStatus) {
      const auto _new_src = ptr(src->choice.reportEventEnrollmentStatus);
      const auto src = _new_src;
      const auto res = process_ReportEventEnrollmentStatus_Response(src);
      container->AssignField("reportEventEnrollmentStatus", res);
    }

    if (src->present ==
        ConfirmedServiceResponse_PR_getEventEnrollmentAttributes) {
      const auto _new_src = ptr(src->choice.getEventEnrollmentAttributes);
      const auto src = _new_src;
      const auto res = process_GetEventEnrollmentAttributes_Response(src);
      container->AssignField("getEventEnrollmentAttributes", res);
    }

    if (src->present ==
        ConfirmedServiceResponse_PR_acknowledgeEventNotification) {
      const auto _new_src = ptr(src->choice.acknowledgeEventNotification);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("acknowledgeEventNotification", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_getAlarmSummary) {
      const auto _new_src = ptr(src->choice.getAlarmSummary);
      const auto src = _new_src;
      const auto res = process_GetAlarmSummary_Response(src);
      container->AssignField("getAlarmSummary", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_getAlarmEnrollmentSummary) {
      const auto _new_src = ptr(src->choice.getAlarmEnrollmentSummary);
      const auto src = _new_src;
      const auto res = process_GetAlarmEnrollmentSummary_Response(src);
      container->AssignField("getAlarmEnrollmentSummary", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_readJournal) {
      const auto _new_src = ptr(src->choice.readJournal);
      const auto src = _new_src;
      const auto res = process_ReadJournal_Response(src);
      container->AssignField("readJournal", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_writeJournal) {
      const auto _new_src = ptr(src->choice.writeJournal);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("writeJournal", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_initializeJournal) {
      const auto _new_src = ptr(src->choice.initializeJournal);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("initializeJournal", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_reportJournalStatus) {
      const auto _new_src = ptr(src->choice.reportJournalStatus);
      const auto src = _new_src;
      const auto res = process_ReportJournalStatus_Response(src);
      container->AssignField("reportJournalStatus", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_createJournal) {
      const auto _new_src = ptr(src->choice.createJournal);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("createJournal", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_deleteJournal) {
      const auto _new_src = ptr(src->choice.deleteJournal);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("deleteJournal", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_getCapabilityList) {
      const auto _new_src = ptr(src->choice.getCapabilityList);
      const auto src = _new_src;
      const auto res = process_GetCapabilityList_Response(src);
      container->AssignField("getCapabilityList", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_fileRead) {
      const auto _new_src = ptr(src->choice.fileRead);
      const auto src = _new_src;
      const auto res = process_FileRead_Response(src);
      container->AssignField("fileRead", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_fileClose) {
      const auto _new_src = ptr(src->choice.fileClose);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("fileClose", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_fileRename) {
      const auto _new_src = ptr(src->choice.fileRename);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("fileRename", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_fileDelete) {
      const auto _new_src = ptr(src->choice.fileDelete);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("fileDelete", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_fileDirectory) {
      const auto _new_src = ptr(src->choice.fileDirectory);
      const auto src = _new_src;
      const auto res = process_FileDirectory_Response(src);
      container->AssignField("fileDirectory", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_FileName(const FileName_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<VectorType>("mms::FileName");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;
      const auto res = convert(src);
      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ObjectName(const ObjectName_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::ObjectName");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == ObjectName_PR_vmd_specific) {
      const auto _new_src = ptr(src->choice.vmd_specific);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("vmd_specific", res);
    }

    if (src->present == ObjectName_PR_domain_specific) {
      const auto _new_src = ptr(src->choice.domain_specific);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "domain_specific");
        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = ptr(src->domainId);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("domainId", res);
        }

        {
          const auto _new_src = ptr(src->itemId);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("itemId", res);
        }

        res = container;
      }

      container->AssignField("domain_specific", res);
    }

    if (src->present == ObjectName_PR_aa_specific) {
      const auto _new_src = ptr(src->choice.aa_specific);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("aa_specific", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Priority(const Priority_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_Initiate_ErrorPDU(const Initiate_ErrorPDU_t *src) {
  const auto res = process_ServiceError(src);
  return res;
}

IntrusivePtr<Val>
process_Initiate_RequestPDU(const Initiate_RequestPDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::Initiate_RequestPDU");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->localDetailCalling) {
      const auto _new_src = ptr(src->localDetailCalling);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("localDetailCalling", res);
    }

    {
      const auto _new_src = ptr(src->proposedMaxServOutstandingCalling);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("proposedMaxServOutstandingCalling", res);
    }

    {
      const auto _new_src = ptr(src->proposedMaxServOutstandingCalled);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("proposedMaxServOutstandingCalled", res);
    }

    if (src->proposedDataStructureNestingLevel) {
      const auto _new_src = ptr(src->proposedDataStructureNestingLevel);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("proposedDataStructureNestingLevel", res);
    }

    {
      const auto _new_src = ptr(src->mmsInitRequestDetail);
      const auto src = _new_src;
      const auto res = process_InitRequestDetail(src);
      container->AssignField("mmsInitRequestDetail", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_InitRequestDetail(const InitRequestDetail_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::InitRequestDetail");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->proposedVersionNumber);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("proposedVersionNumber", res);
    }

    {
      const auto _new_src = ptr(src->proposedParameterCBB);
      const auto src = _new_src;
      const auto res = process_ParameterSupportOptions(src);
      container->AssignField("proposedParameterCBB", res);
    }

    {
      const auto _new_src = ptr(src->servicesSupportedCalling);
      const auto src = _new_src;
      const auto res = process_ServiceSupportOptions(src);
      container->AssignField("servicesSupportedCalling", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_Initiate_ResponsePDU(const Initiate_ResponsePDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::Initiate_ResponsePDU");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->localDetailCalled) {
      const auto _new_src = ptr(src->localDetailCalled);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("localDetailCalled", res);
    }

    {
      const auto _new_src = ptr(src->negociatedMaxServOutstandingCalling);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("negociatedMaxServOutstandingCalling", res);
    }

    {
      const auto _new_src = ptr(src->negociatedMaxServOutstandingCalled);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("negociatedMaxServOutstandingCalled", res);
    }

    if (src->negociatedDataStructureNestingLevel) {
      const auto _new_src = ptr(src->negociatedDataStructureNestingLevel);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("negociatedDataStructureNestingLevel", res);
    }

    {
      const auto _new_src = ptr(src->mmsInitResponseDetail);
      const auto src = _new_src;
      const auto res = process_InitResponseDetail(src);
      container->AssignField("mmsInitResponseDetail", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_InitResponseDetail(const InitResponseDetail_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::InitResponseDetail");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->negociatedVersionNumber);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("negociatedVersionNumber", res);
    }

    {
      const auto _new_src = ptr(src->negociatedParameterCBB);
      const auto src = _new_src;
      const auto res = process_ParameterSupportOptions(src);
      container->AssignField("negociatedParameterCBB", res);
    }

    {
      const auto _new_src = ptr(src->servicesSupportedCalled);
      const auto src = _new_src;
      const auto res = process_ServiceSupportOptions(src);
      container->AssignField("servicesSupportedCalled", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_ParameterSupportOptions(const ParameterSupportOptions_t *src) {
  static const auto type =
      id::find_type<VectorType>("mms::ParameterSupportOptions");
  static IntrusivePtr<EnumType> enum_type = nullptr;
  if (!enum_type) {
    auto subtype = type->Yield();
    if (!subtype || subtype->Tag() != TYPE_ENUM)
      reporter->InternalError("Unable to process 'ParameterSupportOptions': "
                              "%s is not a vector of enums",
                              type->GetName().c_str());
    enum_type = cast_intrusive<EnumType>(subtype);
  }
  auto res = make_intrusive<VectorVal>(type);
  if (src ? is_bit_set(src, 0) : false) /* str1 */
    res->Append(enum_type->GetEnumVal(0));
  if (src ? is_bit_set(src, 1) : false) /* str2 */
    res->Append(enum_type->GetEnumVal(1));
  if (src ? is_bit_set(src, 2) : false) /* vnam */
    res->Append(enum_type->GetEnumVal(2));
  if (src ? is_bit_set(src, 3) : false) /* valt */
    res->Append(enum_type->GetEnumVal(3));
  if (src ? is_bit_set(src, 4) : false) /* vadr */
    res->Append(enum_type->GetEnumVal(4));
  if (src ? is_bit_set(src, 5) : false) /* vsca */
    res->Append(enum_type->GetEnumVal(5));
  if (src ? is_bit_set(src, 6) : false) /* tpy */
    res->Append(enum_type->GetEnumVal(6));
  if (src ? is_bit_set(src, 7) : false) /* vlis */
    res->Append(enum_type->GetEnumVal(7));
  if (src ? is_bit_set(src, 8) : false) /* real */
    res->Append(enum_type->GetEnumVal(8));
  if (src ? is_bit_set(src, 10) : false) /* cei */
    res->Append(enum_type->GetEnumVal(10));
  return res;
}

IntrusivePtr<Val>
process_ServiceSupportOptions(const ServiceSupportOptions_t *src) {
  static const auto type =
      id::find_type<VectorType>("mms::ServiceSupportOptions");
  static IntrusivePtr<EnumType> enum_type = nullptr;
  if (!enum_type) {
    auto subtype = type->Yield();
    if (!subtype || subtype->Tag() != TYPE_ENUM)
      reporter->InternalError("Unable to process 'ServiceSupportOptions': "
                              "%s is not a vector of enums",
                              type->GetName().c_str());
    enum_type = cast_intrusive<EnumType>(subtype);
  }
  auto res = make_intrusive<VectorVal>(type);
  if (src ? is_bit_set(src, 0) : false) /* status */
    res->Append(enum_type->GetEnumVal(0));
  if (src ? is_bit_set(src, 1) : false) /* getNameList */
    res->Append(enum_type->GetEnumVal(1));
  if (src ? is_bit_set(src, 2) : false) /* identify */
    res->Append(enum_type->GetEnumVal(2));
  if (src ? is_bit_set(src, 3) : false) /* rename */
    res->Append(enum_type->GetEnumVal(3));
  if (src ? is_bit_set(src, 4) : false) /* read */
    res->Append(enum_type->GetEnumVal(4));
  if (src ? is_bit_set(src, 5) : false) /* write */
    res->Append(enum_type->GetEnumVal(5));
  if (src ? is_bit_set(src, 6) : false) /* getVariableAccessAttributes */
    res->Append(enum_type->GetEnumVal(6));
  if (src ? is_bit_set(src, 7) : false) /* defineNamedVariable */
    res->Append(enum_type->GetEnumVal(7));
  if (src ? is_bit_set(src, 8) : false) /* defineScatteredAccess */
    res->Append(enum_type->GetEnumVal(8));
  if (src ? is_bit_set(src, 9) : false) /* getScatteredAccessAttributes */
    res->Append(enum_type->GetEnumVal(9));
  if (src ? is_bit_set(src, 10) : false) /* deleteVariableAccess */
    res->Append(enum_type->GetEnumVal(10));
  if (src ? is_bit_set(src, 11) : false) /* defineNamedVariableList */
    res->Append(enum_type->GetEnumVal(11));
  if (src ? is_bit_set(src, 12) : false) /* getNamedVariableListAttributes */
    res->Append(enum_type->GetEnumVal(12));
  if (src ? is_bit_set(src, 13) : false) /* deleteNamedVariableList */
    res->Append(enum_type->GetEnumVal(13));
  if (src ? is_bit_set(src, 14) : false) /* defineNamedType */
    res->Append(enum_type->GetEnumVal(14));
  if (src ? is_bit_set(src, 15) : false) /* getNamedTypeAttributes */
    res->Append(enum_type->GetEnumVal(15));
  if (src ? is_bit_set(src, 16) : false) /* deleteNamedType */
    res->Append(enum_type->GetEnumVal(16));
  if (src ? is_bit_set(src, 17) : false) /* input */
    res->Append(enum_type->GetEnumVal(17));
  if (src ? is_bit_set(src, 18) : false) /* output */
    res->Append(enum_type->GetEnumVal(18));
  if (src ? is_bit_set(src, 19) : false) /* takeControl */
    res->Append(enum_type->GetEnumVal(19));
  if (src ? is_bit_set(src, 20) : false) /* relinquishControl */
    res->Append(enum_type->GetEnumVal(20));
  if (src ? is_bit_set(src, 21) : false) /* defineSemaphore */
    res->Append(enum_type->GetEnumVal(21));
  if (src ? is_bit_set(src, 22) : false) /* deleteSemaphore */
    res->Append(enum_type->GetEnumVal(22));
  if (src ? is_bit_set(src, 23) : false) /* reportSemaphoreStatus */
    res->Append(enum_type->GetEnumVal(23));
  if (src ? is_bit_set(src, 24) : false) /* reportPoolSemaphoreStatus */
    res->Append(enum_type->GetEnumVal(24));
  if (src ? is_bit_set(src, 25) : false) /* reportSemaphoreEntryStatus */
    res->Append(enum_type->GetEnumVal(25));
  if (src ? is_bit_set(src, 26) : false) /* initiateDownloadSequence */
    res->Append(enum_type->GetEnumVal(26));
  if (src ? is_bit_set(src, 27) : false) /* downloadSegment */
    res->Append(enum_type->GetEnumVal(27));
  if (src ? is_bit_set(src, 28) : false) /* terminateDownloadSequence */
    res->Append(enum_type->GetEnumVal(28));
  if (src ? is_bit_set(src, 29) : false) /* initiateUploadSequence */
    res->Append(enum_type->GetEnumVal(29));
  if (src ? is_bit_set(src, 30) : false) /* uploadSegment */
    res->Append(enum_type->GetEnumVal(30));
  if (src ? is_bit_set(src, 31) : false) /* terminateUploadSequence */
    res->Append(enum_type->GetEnumVal(31));
  if (src ? is_bit_set(src, 32) : false) /* requestDomainDownload */
    res->Append(enum_type->GetEnumVal(32));
  if (src ? is_bit_set(src, 33) : false) /* requestDomainUpload */
    res->Append(enum_type->GetEnumVal(33));
  if (src ? is_bit_set(src, 34) : false) /* loadDomainContent */
    res->Append(enum_type->GetEnumVal(34));
  if (src ? is_bit_set(src, 35) : false) /* storeDomainContent */
    res->Append(enum_type->GetEnumVal(35));
  if (src ? is_bit_set(src, 36) : false) /* deleteDomain */
    res->Append(enum_type->GetEnumVal(36));
  if (src ? is_bit_set(src, 37) : false) /* getDomainAttributes */
    res->Append(enum_type->GetEnumVal(37));
  if (src ? is_bit_set(src, 38) : false) /* createProgramInvocation */
    res->Append(enum_type->GetEnumVal(38));
  if (src ? is_bit_set(src, 39) : false) /* deleteProgramInvocation */
    res->Append(enum_type->GetEnumVal(39));
  if (src ? is_bit_set(src, 40) : false) /* start */
    res->Append(enum_type->GetEnumVal(40));
  if (src ? is_bit_set(src, 41) : false) /* stop */
    res->Append(enum_type->GetEnumVal(41));
  if (src ? is_bit_set(src, 42) : false) /* resume */
    res->Append(enum_type->GetEnumVal(42));
  if (src ? is_bit_set(src, 43) : false) /* reset */
    res->Append(enum_type->GetEnumVal(43));
  if (src ? is_bit_set(src, 44) : false) /* kill */
    res->Append(enum_type->GetEnumVal(44));
  if (src ? is_bit_set(src, 45) : false) /* getProgramInvocationAttributes */
    res->Append(enum_type->GetEnumVal(45));
  if (src ? is_bit_set(src, 46) : false) /* obtainFile */
    res->Append(enum_type->GetEnumVal(46));
  if (src ? is_bit_set(src, 47) : false) /* defineEventCondition */
    res->Append(enum_type->GetEnumVal(47));
  if (src ? is_bit_set(src, 48) : false) /* deleteEventCondition */
    res->Append(enum_type->GetEnumVal(48));
  if (src ? is_bit_set(src, 49) : false) /* getEventConditionAttributes */
    res->Append(enum_type->GetEnumVal(49));
  if (src ? is_bit_set(src, 50) : false) /* reportEventConditionStatus */
    res->Append(enum_type->GetEnumVal(50));
  if (src ? is_bit_set(src, 51) : false) /* alterEventConditionMonitoring */
    res->Append(enum_type->GetEnumVal(51));
  if (src ? is_bit_set(src, 52) : false) /* triggerEvent */
    res->Append(enum_type->GetEnumVal(52));
  if (src ? is_bit_set(src, 53) : false) /* defineEventAction */
    res->Append(enum_type->GetEnumVal(53));
  if (src ? is_bit_set(src, 54) : false) /* deleteEventAction */
    res->Append(enum_type->GetEnumVal(54));
  if (src ? is_bit_set(src, 55) : false) /* getEventActionAttributes */
    res->Append(enum_type->GetEnumVal(55));
  if (src ? is_bit_set(src, 56) : false) /* reportActionStatus */
    res->Append(enum_type->GetEnumVal(56));
  if (src ? is_bit_set(src, 57) : false) /* defineEventEnrollment */
    res->Append(enum_type->GetEnumVal(57));
  if (src ? is_bit_set(src, 58) : false) /* deleteEventEnrollment */
    res->Append(enum_type->GetEnumVal(58));
  if (src ? is_bit_set(src, 59) : false) /* alterEventEnrollment */
    res->Append(enum_type->GetEnumVal(59));
  if (src ? is_bit_set(src, 60) : false) /* reportEventEnrollmentStatus */
    res->Append(enum_type->GetEnumVal(60));
  if (src ? is_bit_set(src, 61) : false) /* getEventEnrollmentAttributes */
    res->Append(enum_type->GetEnumVal(61));
  if (src ? is_bit_set(src, 62) : false) /* acknowledgeEventNotification */
    res->Append(enum_type->GetEnumVal(62));
  if (src ? is_bit_set(src, 63) : false) /* getAlarmSummary */
    res->Append(enum_type->GetEnumVal(63));
  if (src ? is_bit_set(src, 64) : false) /* getAlarmEnrollmentSummary */
    res->Append(enum_type->GetEnumVal(64));
  if (src ? is_bit_set(src, 65) : false) /* readJournal */
    res->Append(enum_type->GetEnumVal(65));
  if (src ? is_bit_set(src, 66) : false) /* writeJournal */
    res->Append(enum_type->GetEnumVal(66));
  if (src ? is_bit_set(src, 67) : false) /* initializeJournal */
    res->Append(enum_type->GetEnumVal(67));
  if (src ? is_bit_set(src, 68) : false) /* reportJournalStatus */
    res->Append(enum_type->GetEnumVal(68));
  if (src ? is_bit_set(src, 69) : false) /* createJournal */
    res->Append(enum_type->GetEnumVal(69));
  if (src ? is_bit_set(src, 70) : false) /* deleteJournal */
    res->Append(enum_type->GetEnumVal(70));
  if (src ? is_bit_set(src, 71) : false) /* getCapabilityList */
    res->Append(enum_type->GetEnumVal(71));
  if (src ? is_bit_set(src, 72) : false) /* fileOpen */
    res->Append(enum_type->GetEnumVal(72));
  if (src ? is_bit_set(src, 73) : false) /* fileRead */
    res->Append(enum_type->GetEnumVal(73));
  if (src ? is_bit_set(src, 74) : false) /* fileClose */
    res->Append(enum_type->GetEnumVal(74));
  if (src ? is_bit_set(src, 75) : false) /* fileRename */
    res->Append(enum_type->GetEnumVal(75));
  if (src ? is_bit_set(src, 76) : false) /* fileDelete */
    res->Append(enum_type->GetEnumVal(76));
  if (src ? is_bit_set(src, 77) : false) /* fileDirectory */
    res->Append(enum_type->GetEnumVal(77));
  if (src ? is_bit_set(src, 78) : false) /* unsolicitedStatus */
    res->Append(enum_type->GetEnumVal(78));
  if (src ? is_bit_set(src, 79) : false) /* informationReport */
    res->Append(enum_type->GetEnumVal(79));
  if (src ? is_bit_set(src, 80) : false) /* eventNotification */
    res->Append(enum_type->GetEnumVal(80));
  if (src ? is_bit_set(src, 81) : false) /* attachToEventCondition */
    res->Append(enum_type->GetEnumVal(81));
  if (src ? is_bit_set(src, 82) : false) /* attachToSemaphore */
    res->Append(enum_type->GetEnumVal(82));
  if (src ? is_bit_set(src, 83) : false) /* conclude */
    res->Append(enum_type->GetEnumVal(83));
  if (src ? is_bit_set(src, 84) : false) /* cancel */
    res->Append(enum_type->GetEnumVal(84));
  return res;
}

IntrusivePtr<Val> process_Conclude_ErrorPDU(const Conclude_ErrorPDU_t *src) {
  const auto res = process_ServiceError(src);
  return res;
}

IntrusivePtr<Val> process_Cancel_RequestPDU(const Cancel_RequestPDU_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_Cancel_ResponsePDU(const Cancel_ResponsePDU_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_Cancel_ErrorPDU(const Cancel_ErrorPDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Cancel_ErrorPDU");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->originalInvokeID);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("originalInvokeID", res);
    }

    {
      const auto _new_src = ptr(src->serviceError);
      const auto src = _new_src;
      const auto res = process_ServiceError(src);
      container->AssignField("serviceError", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ServiceError(const ServiceError_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::ServiceError");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->errorClass);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "errorClass");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present == ServiceError__errorClass_PR_vmd_state) {
          const auto _new_src = ptr(src->choice.vmd_state);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("vmd_state", res);
        }

        if (src->present == ServiceError__errorClass_PR_application_reference) {
          const auto _new_src = ptr(src->choice.application_reference);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("application_reference", res);
        }

        if (src->present == ServiceError__errorClass_PR_definition) {
          const auto _new_src = ptr(src->choice.definition);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("definition", res);
        }

        if (src->present == ServiceError__errorClass_PR_resource) {
          const auto _new_src = ptr(src->choice.resource);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("resource", res);
        }

        if (src->present == ServiceError__errorClass_PR_service) {
          const auto _new_src = ptr(src->choice.service);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("service", res);
        }

        if (src->present == ServiceError__errorClass_PR_service_preempt) {
          const auto _new_src = ptr(src->choice.service_preempt);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("service_preempt", res);
        }

        if (src->present == ServiceError__errorClass_PR_time_resolution) {
          const auto _new_src = ptr(src->choice.time_resolution);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("time_resolution", res);
        }

        if (src->present == ServiceError__errorClass_PR_access) {
          const auto _new_src = ptr(src->choice.access);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("access", res);
        }

        if (src->present == ServiceError__errorClass_PR_initiate) {
          const auto _new_src = ptr(src->choice.initiate);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("initiate", res);
        }

        if (src->present == ServiceError__errorClass_PR_conclude) {
          const auto _new_src = ptr(src->choice.conclude);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("conclude", res);
        }

        if (src->present == ServiceError__errorClass_PR_cancel) {
          const auto _new_src = ptr(src->choice.cancel);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("_cancel", res);
        }

        if (src->present == ServiceError__errorClass_PR_file) {
          const auto _new_src = ptr(src->choice.file);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("_file", res);
        }

        if (src->present == ServiceError__errorClass_PR_others) {
          const auto _new_src = ptr(src->choice.others);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("others", res);
        }

        res = container;
      }

      container->AssignField("errorClass", res);
    }

    if (src->additionalCode) {
      const auto _new_src = ptr(src->additionalCode);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("additionalCode", res);
    }

    if (src->additionalDescription) {
      const auto _new_src = ptr(src->additionalDescription);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("additionalDescription", res);
    }

    if (src->serviceSpecificInformation) {
      const auto _new_src = ptr(src->serviceSpecificInformation);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "serviceSpecificInformation");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present ==
            ServiceError__serviceSpecificInformation_PR_obtainFile) {
          const auto _new_src = ptr(src->choice.obtainFile);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("obtainFile", res);
        }

        if (src->present == ServiceError__serviceSpecificInformation_PR_start) {
          const auto _new_src = ptr(src->choice.start);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("start", res);
        }

        if (src->present == ServiceError__serviceSpecificInformation_PR_stop) {
          const auto _new_src = ptr(src->choice.stop);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("stop", res);
        }

        if (src->present ==
            ServiceError__serviceSpecificInformation_PR_resume) {
          const auto _new_src = ptr(src->choice.resume);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("resume", res);
        }

        if (src->present == ServiceError__serviceSpecificInformation_PR_reset) {
          const auto _new_src = ptr(src->choice.reset);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("reset", res);
        }

        if (src->present ==
            ServiceError__serviceSpecificInformation_PR_deleteVariableAccess) {
          const auto _new_src = ptr(src->choice.deleteVariableAccess);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("deleteVariableAccess", res);
        }

        if (src->present ==
            ServiceError__serviceSpecificInformation_PR_deleteNamedVariableList) {
          const auto _new_src = ptr(src->choice.deleteNamedVariableList);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("deleteNamedVariableList", res);
        }

        if (src->present ==
            ServiceError__serviceSpecificInformation_PR_deleteNamedType) {
          const auto _new_src = ptr(src->choice.deleteNamedType);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("deleteNamedType", res);
        }

        if (src->present ==
            ServiceError__serviceSpecificInformation_PR_defineEventEnrollment_Error) {
          const auto _new_src = ptr(src->choice.defineEventEnrollment_Error);
          const auto src = _new_src;
          const auto res = process_ObjectName(src);
          container->AssignField("defineEventEnrollment_Error", res);
        }

        if (src->present ==
            ServiceError__serviceSpecificInformation_PR_fileRename) {
          const auto _new_src = ptr(src->choice.fileRename);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("fileRename", res);
        }

        if (src->present ==
            ServiceError__serviceSpecificInformation_PR_additionalService) {
          const auto _new_src = ptr(src->choice.additionalService);
          const auto src = _new_src;
          const auto res = process_AdditionalService_Error(src);
          container->AssignField("additionalService", res);
        }

        if (src->present ==
            ServiceError__serviceSpecificInformation_PR_changeAccessControl) {
          const auto _new_src = ptr(src->choice.changeAccessControl);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("changeAccessControl", res);
        }

        res = container;
      }

      container->AssignField("serviceSpecificInformation", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_AdditionalService_Error(const AdditionalService_Error_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::AdditionalService_Error");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == AdditionalService_Error_PR_defineEcl) {
      const auto _new_src = ptr(src->choice.defineEcl);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("defineEcl", res);
    }

    if (src->present == AdditionalService_Error_PR_addECLReference) {
      const auto _new_src = ptr(src->choice.addECLReference);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("addECLReference", res);
    }

    if (src->present == AdditionalService_Error_PR_removeECLReference) {
      const auto _new_src = ptr(src->choice.removeECLReference);
      const auto src = _new_src;
      const auto res = process_RemoveEventConditionListReference_Error(src);
      container->AssignField("removeECLReference", res);
    }

    if (src->present == AdditionalService_Error_PR_initiateUC) {
      const auto _new_src = ptr(src->choice.initiateUC);
      const auto src = _new_src;
      const auto res = process_InitiateUnitControl_Error(src);
      container->AssignField("initiateUC", res);
    }

    if (src->present == AdditionalService_Error_PR_startUC) {
      const auto _new_src = ptr(src->choice.startUC);
      const auto src = _new_src;
      const auto res = process_StartUnitControl_Error(src);
      container->AssignField("startUC", res);
    }

    if (src->present == AdditionalService_Error_PR_stopUC) {
      const auto _new_src = ptr(src->choice.stopUC);
      const auto src = _new_src;
      const auto res = process_StopUnitControl_Error(src);
      container->AssignField("stopUC", res);
    }

    if (src->present == AdditionalService_Error_PR_deleteUC) {
      const auto _new_src = ptr(src->choice.deleteUC);
      const auto src = _new_src;
      const auto res = process_DeleteUnitControl_Error(src);
      container->AssignField("deleteUC", res);
    }

    if (src->present == AdditionalService_Error_PR_loadUCFromFile) {
      const auto _new_src = ptr(src->choice.loadUCFromFile);
      const auto src = _new_src;
      const auto res = process_LoadUnitControlFromFile_Error(src);
      container->AssignField("loadUCFromFile", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_DefineEventConditionList_Error(
    const DefineEventConditionList_Error_t *src) {
  const auto res = process_ObjectName(src);
  return res;
}

IntrusivePtr<Val> process_AddEventConditionListReference_Error(
    const AddEventConditionListReference_Error_t *src) {
  const auto res = process_ObjectName(src);
  return res;
}

IntrusivePtr<Val> process_RemoveEventConditionListReference_Error(
    const RemoveEventConditionListReference_Error_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>(
        "mms::RemoveEventConditionListReference_Error");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present ==
        RemoveEventConditionListReference_Error_PR_eventCondition) {
      const auto _new_src = ptr(src->choice.eventCondition);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventCondition", res);
    }

    if (src->present ==
        RemoveEventConditionListReference_Error_PR_eventConditionList) {
      const auto _new_src = ptr(src->choice.eventConditionList);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventConditionList", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_InitiateUnitControl_Error(const InitiateUnitControl_Error_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::InitiateUnitControl_Error");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == InitiateUnitControl_Error_PR_domain) {
      const auto _new_src = ptr(src->choice.domain);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("_domain", res);
    }

    if (src->present == InitiateUnitControl_Error_PR_programInvocation) {
      const auto _new_src = ptr(src->choice.programInvocation);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("programInvocation", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_StartUnitControl_Error(const StartUnitControl_Error_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::StartUnitControl_Error");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->programInvocationName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("programInvocationName", res);
    }

    {
      const auto _new_src = ptr(src->programInvocationState);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("programInvocationState", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_StopUnitControl_Error(const StopUnitControl_Error_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::StopUnitControl_Error");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->programInvocationName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("programInvocationName", res);
    }

    {
      const auto _new_src = ptr(src->programInvocationState);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("programInvocationState", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_DeleteUnitControl_Error(const DeleteUnitControl_Error_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DeleteUnitControl_Error");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == DeleteUnitControl_Error_PR_domain) {
      const auto _new_src = ptr(src->choice.domain);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("_domain", res);
    }

    if (src->present == DeleteUnitControl_Error_PR_programInvocation) {
      const auto _new_src = ptr(src->choice.programInvocation);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("programInvocation", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_LoadUnitControlFromFile_Error(
    const LoadUnitControlFromFile_Error_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::LoadUnitControlFromFile_Error");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == LoadUnitControlFromFile_Error_PR_none) {
      const auto _new_src = ptr(src->choice.none);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("none", res);
    }

    if (src->present == LoadUnitControlFromFile_Error_PR_domain) {
      const auto _new_src = ptr(src->choice.domain);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("_domain", res);
    }

    if (src->present == LoadUnitControlFromFile_Error_PR_programInvocation) {
      const auto _new_src = ptr(src->choice.programInvocation);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("programInvocation", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_ChangeAccessControl_Error(const ChangeAccessControl_Error_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_RejectPDU(const RejectPDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::RejectPDU");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->originalInvokeID) {
      const auto _new_src = ptr(src->originalInvokeID);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("originalInvokeID", res);
    }

    {
      const auto _new_src = ptr(src->rejectReason);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "rejectReason");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present == RejectPDU__rejectReason_PR_confirmed_requestPDU) {
          const auto _new_src = ptr(src->choice.confirmed_requestPDU);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("confirmed_requestPDU", res);
        }

        if (src->present == RejectPDU__rejectReason_PR_confirmed_responsePDU) {
          const auto _new_src = ptr(src->choice.confirmed_responsePDU);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("confirmed_responsePDU", res);
        }

        if (src->present == RejectPDU__rejectReason_PR_confirmed_errorPDU) {
          const auto _new_src = ptr(src->choice.confirmed_errorPDU);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("confirmed_errorPDU", res);
        }

        if (src->present == RejectPDU__rejectReason_PR_unconfirmedPDU) {
          const auto _new_src = ptr(src->choice.unconfirmedPDU);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("unconfirmedPDU", res);
        }

        if (src->present == RejectPDU__rejectReason_PR_pdu_error) {
          const auto _new_src = ptr(src->choice.pdu_error);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("pdu_error", res);
        }

        if (src->present == RejectPDU__rejectReason_PR_cancel_requestPDU) {
          const auto _new_src = ptr(src->choice.cancel_requestPDU);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("cancel_requestPDU", res);
        }

        if (src->present == RejectPDU__rejectReason_PR_cancel_responsePDU) {
          const auto _new_src = ptr(src->choice.cancel_responsePDU);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("cancel_responsePDU", res);
        }

        if (src->present == RejectPDU__rejectReason_PR_cancel_errorPDU) {
          const auto _new_src = ptr(src->choice.cancel_errorPDU);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("cancel_errorPDU", res);
        }

        if (src->present == RejectPDU__rejectReason_PR_conclude_requestPDU) {
          const auto _new_src = ptr(src->choice.conclude_requestPDU);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("conclude_requestPDU", res);
        }

        if (src->present == RejectPDU__rejectReason_PR_conclude_responsePDU) {
          const auto _new_src = ptr(src->choice.conclude_responsePDU);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("conclude_responsePDU", res);
        }

        if (src->present == RejectPDU__rejectReason_PR_conclude_errorPDU) {
          const auto _new_src = ptr(src->choice.conclude_errorPDU);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("conclude_errorPDU", res);
        }

        res = container;
      }

      container->AssignField("rejectReason", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Status_Response(const Status_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Status_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->vmdLogicalStatus);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("vmdLogicalStatus", res);
    }

    {
      const auto _new_src = ptr(src->vmdPhysicalStatus);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("vmdPhysicalStatus", res);
    }

    if (src->localDetail) {
      const auto _new_src = ptr(src->localDetail);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("localDetail", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_UnsolicitedStatus(const UnsolicitedStatus_t *src) {
  const auto res = process_Status_Response(src);
  return res;
}

IntrusivePtr<Val> process_ObjectScope(const ObjectScope_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::ObjectScope");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == ObjectScope_PR_vmdSpecific) {
      const auto _new_src = ptr(src->choice.vmdSpecific);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("vmdSpecific", res);
    }

    if (src->present == ObjectScope_PR_domainSpecific) {
      const auto _new_src = ptr(src->choice.domainSpecific);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("domainSpecific", res);
    }

    if (src->present == ObjectScope_PR_aaSpecific) {
      const auto _new_src = ptr(src->choice.aaSpecific);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("aaSpecific", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_GetNameList_Request(const GetNameList_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetNameList_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->extendedObjectClass);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "extendedObjectClass");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present ==
            GetNameList_Request__extendedObjectClass_PR_objectClass) {
          const auto _new_src = ptr(src->choice.objectClass);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("objectClass", res);
        }

        res = container;
      }

      container->AssignField("extendedObjectClass", res);
    }

    {
      const auto _new_src = ptr(src->objectScope);
      const auto src = _new_src;
      const auto res = process_ObjectScope(src);
      container->AssignField("objectScope", res);
    }

    if (src->continueAfter) {
      const auto _new_src = ptr(src->continueAfter);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("continueAfter", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_GetNameList_Response(const GetNameList_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetNameList_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->listOfIdentifier);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfIdentifier");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = convert(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfIdentifier", res);
    }

    {
      const std::remove_pointer<decltype(src->moreFollows)>::type
          default_value = 1;
      const auto _new_src =
          ptr(src->moreFollows ? src->moreFollows : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("moreFollows", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Identify_Response(const Identify_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::Identify_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->vendorName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("vendorName", res);
    }

    {
      const auto _new_src = ptr(src->modelName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("modelName", res);
    }

    {
      const auto _new_src = ptr(src->revision);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("revision", res);
    }

    if (src->listOfAbstractSyntaxes) {
      const auto _new_src = ptr(src->listOfAbstractSyntaxes);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfAbstractSyntaxes");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = convert(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfAbstractSyntaxes", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Rename_Request(const Rename_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Rename_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->extendedObjectClass);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "extendedObjectClass");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present ==
            Rename_Request__extendedObjectClass_PR_objectClass) {
          const auto _new_src = ptr(src->choice.objectClass);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("objectClass", res);
        }

        res = container;
      }

      container->AssignField("extendedObjectClass", res);
    }

    {
      const auto _new_src = ptr(src->currentName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("currentName", res);
    }

    {
      const auto _new_src = ptr(src->newIdentifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("newIdentifier", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_GetCapabilityList_Request(const GetCapabilityList_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetCapabilityList_Request");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->continueAfter) {
      const auto _new_src = ptr(src->continueAfter);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("continueAfter", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_GetCapabilityList_Response(const GetCapabilityList_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetCapabilityList_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->listOfCapabilities);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfCapabilities");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = convert(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfCapabilities", res);
    }

    {
      const std::remove_pointer<decltype(src->moreFollows)>::type
          default_value = 1;
      const auto _new_src =
          ptr(src->moreFollows ? src->moreFollows : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("moreFollows", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_InitiateDownloadSequence_Request(
    const InitiateDownloadSequence_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::InitiateDownloadSequence_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->domainName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("domainName", res);
    }

    {
      const auto _new_src = ptr(src->listOfCapabilities);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfCapabilities");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = convert(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfCapabilities", res);
    }

    {
      const auto _new_src = ptr(src->sharable);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("sharable", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_DownloadSegment_Request(const DownloadSegment_Request_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val>
process_DownloadSegment_Response(const DownloadSegment_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DownloadSegment_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->loadData);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "loadData");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present == DownloadSegment_Response__loadData_PR_non_coded) {
          const auto _new_src = ptr(src->choice.non_coded);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("non_coded", res);
        }

        if (src->present == DownloadSegment_Response__loadData_PR_coded) {
          const auto _new_src = ptr(src->choice.coded);
          const auto src = _new_src;
          const auto res = process_EXTERNALt(src);
          container->AssignField("coded", res);
        }

        res = container;
      }

      container->AssignField("loadData", res);
    }

    {
      const std::remove_pointer<decltype(src->moreFollows)>::type
          default_value = 1;
      const auto _new_src =
          ptr(src->moreFollows ? src->moreFollows : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("moreFollows", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_TerminateDownloadSequence_Request(
    const TerminateDownloadSequence_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::TerminateDownloadSequence_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->domainName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("domainName", res);
    }

    if (src->discard) {
      const auto _new_src = ptr(src->discard);
      const auto src = _new_src;
      const auto res = process_ServiceError(src);
      container->AssignField("discard", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_InitiateUploadSequence_Request(
    const InitiateUploadSequence_Request_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_InitiateUploadSequence_Response(
    const InitiateUploadSequence_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::InitiateUploadSequence_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->ulsmID);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("ulsmID", res);
    }

    {
      const auto _new_src = ptr(src->listOfCapabilities);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfCapabilities");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = convert(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfCapabilities", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_UploadSegment_Request(const UploadSegment_Request_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val>
process_UploadSegment_Response(const UploadSegment_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::UploadSegment_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->loadData);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "loadData");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present == UploadSegment_Response__loadData_PR_non_coded) {
          const auto _new_src = ptr(src->choice.non_coded);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("non_coded", res);
        }

        if (src->present == UploadSegment_Response__loadData_PR_coded) {
          const auto _new_src = ptr(src->choice.coded);
          const auto src = _new_src;
          const auto res = process_EXTERNALt(src);
          container->AssignField("coded", res);
        }

        res = container;
      }

      container->AssignField("loadData", res);
    }

    {
      const std::remove_pointer<decltype(src->moreFollows)>::type
          default_value = 1;
      const auto _new_src =
          ptr(src->moreFollows ? src->moreFollows : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("moreFollows", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_TerminateUploadSequence_Request(
    const TerminateUploadSequence_Request_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_RequestDomainDownload_Request(
    const RequestDomainDownload_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::RequestDomainDownload_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->domainName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("domainName", res);
    }

    if (src->listOfCapabilities) {
      const auto _new_src = ptr(src->listOfCapabilities);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfCapabilities");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = convert(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfCapabilities", res);
    }

    {
      const auto _new_src = ptr(src->sharable);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("sharable", res);
    }

    {
      const auto _new_src = ptr(src->fileName);
      const auto src = _new_src;
      const auto res = process_FileName(src);
      container->AssignField("fileName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_RequestDomainUpload_Request(const RequestDomainUpload_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::RequestDomainUpload_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->domainName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("domainName", res);
    }

    {
      const auto _new_src = ptr(src->fileName);
      const auto src = _new_src;
      const auto res = process_FileName(src);
      container->AssignField("fileName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_LoadDomainContent_Request(const LoadDomainContent_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::LoadDomainContent_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->domainName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("domainName", res);
    }

    if (src->listOfCapabilities) {
      const auto _new_src = ptr(src->listOfCapabilities);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfCapabilities");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = convert(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfCapabilities", res);
    }

    {
      const auto _new_src = ptr(src->sharable);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("sharable", res);
    }

    {
      const auto _new_src = ptr(src->fileName);
      const auto src = _new_src;
      const auto res = process_FileName(src);
      container->AssignField("fileName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_StoreDomainContent_Request(const StoreDomainContent_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::StoreDomainContent_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->domainName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("domainName", res);
    }

    {
      const auto _new_src = ptr(src->filenName);
      const auto src = _new_src;
      const auto res = process_FileName(src);
      container->AssignField("filenName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_DeleteDomain_Request(const DeleteDomain_Request_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val>
process_GetDomainAttributes_Request(const GetDomainAttributes_Request_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_GetDomainAttributes_Response(
    const GetDomainAttributes_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetDomainAttributes_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->listOfCapabilities);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfCapabilities");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = convert(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfCapabilities", res);
    }

    {
      const auto _new_src = ptr(src->state);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("state", res);
    }

    {
      const auto _new_src = ptr(src->mmsDeletable);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mmsDeletable", res);
    }

    {
      const auto _new_src = ptr(src->sharable);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("sharable", res);
    }

    {
      const auto _new_src = ptr(src->listOfProgramInvocations);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfProgramInvocations");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = convert(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfProgramInvocations", res);
    }

    {
      const auto _new_src = ptr(src->uploadInProgress);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("uploadInProgress", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_CreateProgramInvocation_Request(
    const CreateProgramInvocation_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::CreateProgramInvocation_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->programInvocationName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("programInvocationName", res);
    }

    {
      const auto _new_src = ptr(src->listOfDomainName);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfDomainName");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = convert(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfDomainName", res);
    }

    {
      const std::remove_pointer<decltype(src->reusable)>::type default_value =
          1;
      const auto _new_src = ptr(src->reusable ? src->reusable : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("reusable", res);
    }

    if (src->monitorType) {
      const auto _new_src = ptr(src->monitorType);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("monitorType", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_DeleteProgramInvocation_Request(
    const DeleteProgramInvocation_Request_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_Start_Request(const Start_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Start_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->programInvocationName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("programInvocationName", res);
    }

    if (src->executionArgument) {
      const auto _new_src = ptr(src->executionArgument);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "executionArgument");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present == Start_Request__executionArgument_PR_simpleString) {
          const auto _new_src = ptr(src->choice.simpleString);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("simpleString", res);
        }

        if (src->present == Start_Request__executionArgument_PR_encodedString) {
          const auto _new_src = ptr(src->choice.encodedString);
          const auto src = _new_src;
          const auto res = process_EXTERNALt(src);
          container->AssignField("encodedString", res);
        }

        res = container;
      }

      container->AssignField("executionArgument", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Start_Error(const Start_Error_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_Stop_Request(const Stop_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Stop_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->programInvocationName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("programInvocationName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Stop_Error(const Stop_Error_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_Resume_Request(const Resume_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Resume_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->programInvocationName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("programInvocationName", res);
    }

    if (src->executionArgument) {
      const auto _new_src = ptr(src->executionArgument);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "executionArgument");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present == Resume_Request__executionArgument_PR_simpleString) {
          const auto _new_src = ptr(src->choice.simpleString);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("simpleString", res);
        }

        if (src->present ==
            Resume_Request__executionArgument_PR_encodedString) {
          const auto _new_src = ptr(src->choice.encodedString);
          const auto src = _new_src;
          const auto res = process_EXTERNALt(src);
          container->AssignField("encodedString", res);
        }

        res = container;
      }

      container->AssignField("executionArgument", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Resume_Error(const Resume_Error_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_Reset_Request(const Reset_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Reset_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->programInvocationName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("programInvocationName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Reset_Error(const Reset_Error_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_Kill_Request(const Kill_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Kill_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->programInvocationName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("programInvocationName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_GetProgramInvocationAttributes_Request(
    const GetProgramInvocationAttributes_Request_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_GetProgramInvocationAttributes_Response(
    const GetProgramInvocationAttributes_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>(
        "mms::GetProgramInvocationAttributes_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->state);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("state", res);
    }

    {
      const auto _new_src = ptr(src->listOfDomainNames);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfDomainNames");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = convert(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfDomainNames", res);
    }

    {
      const auto _new_src = ptr(src->mmsDeletable);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mmsDeletable", res);
    }

    {
      const auto _new_src = ptr(src->reusable);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("reusable", res);
    }

    {
      const auto _new_src = ptr(src->monitor);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("monitor", res);
    }

    {
      const auto _new_src = ptr(src->startArgument);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("startArgument", res);
    }

    if (src->executionArgument) {
      const auto _new_src = ptr(src->executionArgument);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "executionArgument");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present ==
            GetProgramInvocationAttributes_Response__executionArgument_PR_simpleString) {
          const auto _new_src = ptr(src->choice.simpleString);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("simpleString", res);
        }

        if (src->present ==
            GetProgramInvocationAttributes_Response__executionArgument_PR_encodedString) {
          const auto _new_src = ptr(src->choice.encodedString);
          const auto src = _new_src;
          const auto res = process_EXTERNALt(src);
          container->AssignField("encodedString", res);
        }

        res = container;
      }

      container->AssignField("executionArgument", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_TypeSpecification(const TypeSpecification_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::TypeSpecification");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == TypeSpecification_PR_typeName) {
      const auto _new_src = ptr(src->choice.typeName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("typeName", res);
    }

    if (src->present == TypeSpecification_PR_array) {
      const auto _new_src = ptr(src->choice.array);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type = get_field_type<RecordType>(container, "array");
        const auto container = make_intrusive<RecordVal>(type);

        {
          const std::remove_pointer<decltype(src->packed)>::type default_value =
              0;
          const auto _new_src = ptr(src->packed ? src->packed : &default_value);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("packed", res);
        }

        {
          const auto _new_src = ptr(src->numberOfElements);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("numberOfElements", res);
        }

        {
          const auto _new_src = ptr(src->elementType);
          const auto src = _new_src;
          const auto res = process_TypeSpecification(src);
          container->AssignField("elementType", res);
        }

        res = container;
      }

      container->AssignField("array", res);
    }

    if (src->present == TypeSpecification_PR_structure) {
      const auto _new_src = ptr(src->choice.structure);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "structure");
        const auto container = make_intrusive<RecordVal>(type);

        {
          const std::remove_pointer<decltype(src->packed)>::type default_value =
              0;
          const auto _new_src = ptr(src->packed ? src->packed : &default_value);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("packed", res);
        }

        {
          const auto _new_src = ptr(src->components);
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {
            static const auto type =
                get_field_type<VectorType>(container, "components");
            const auto container = make_intrusive<VectorVal>(type);
            for (int i = 0; i < src->list.count; i++) {
              const auto _new_src = src->list.array[i];
              const auto src = _new_src;

              IntrusivePtr<Val> res;
              {
                static const auto type = get_field_type<RecordType>(container);
                const auto container = make_intrusive<RecordVal>(type);

                if (src->componentName) {
                  const auto _new_src = ptr(src->componentName);
                  const auto src = _new_src;
                  const auto res = convert(src);
                  container->AssignField("componentName", res);
                }

                {
                  const auto _new_src = ptr(src->componentType);
                  const auto src = _new_src;
                  const auto res = process_TypeSpecification(src);
                  container->AssignField("componentType", res);
                }

                res = container;
              }

              container->Append(res);
            }
            res = container;
          }

          container->AssignField("components", res);
        }

        res = container;
      }

      container->AssignField("structure", res);
    }

    if (src->present == TypeSpecification_PR_boolean) {
      const auto _new_src = ptr(src->choice.boolean);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("boolean", res);
    }

    if (src->present == TypeSpecification_PR_bit_string) {
      const auto _new_src = ptr(src->choice.bit_string);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("bit_string", res);
    }

    if (src->present == TypeSpecification_PR_integer) {
      const auto _new_src = ptr(src->choice.integer);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("integer", res);
    }

    if (src->present == TypeSpecification_PR_unsigned) {
      const auto _new_src = ptr(src->choice.Unsigned);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("unsigned", res);
    }

    if (src->present == TypeSpecification_PR_octet_string) {
      const auto _new_src = ptr(src->choice.octet_string);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("octet_string", res);
    }

    if (src->present == TypeSpecification_PR_visible_string) {
      const auto _new_src = ptr(src->choice.visible_string);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("visible_string", res);
    }

    if (src->present == TypeSpecification_PR_generalized_time) {
      const auto _new_src = ptr(src->choice.generalized_time);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("generalized_time", res);
    }

    if (src->present == TypeSpecification_PR_binary_time) {
      const auto _new_src = ptr(src->choice.binary_time);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("binary_time", res);
    }

    if (src->present == TypeSpecification_PR_bcd) {
      const auto _new_src = ptr(src->choice.bcd);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("bcd", res);
    }

    if (src->present == TypeSpecification_PR_objId) {
      const auto _new_src = ptr(src->choice.objId);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("objId", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_AlternateAccess(const AlternateAccess_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<VectorType>("mms::AlternateAccess");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type = get_field_type<RecordType>(container);
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present == AlternateAccess__Member_PR_unnamed) {
          const auto _new_src = ptr(src->choice.unnamed);
          const auto src = _new_src;
          const auto res = process_AlternateAccessSelection(src);
          container->AssignField("unnamed", res);
        }

        if (src->present == AlternateAccess__Member_PR_named) {
          const auto _new_src = ptr(src->choice.named);
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {
            static const auto type =
                get_field_type<RecordType>(container, "named");
            const auto container = make_intrusive<RecordVal>(type);

            {
              const auto _new_src = ptr(src->componentName);
              const auto src = _new_src;
              const auto res = convert(src);
              container->AssignField("componentName", res);
            }

            {
              const auto _new_src = ptr(src->accesst);
              const auto src = _new_src;
              const auto res = process_AlternateAccessSelection(src);
              container->AssignField("accesst", res);
            }

            res = container;
          }

          container->AssignField("named", res);
        }

        res = container;
      }

      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_AlternateAccessSelection(const AlternateAccessSelection_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::AlternateAccessSelection");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == AlternateAccessSelection_PR_selectAlternateAccess) {
      const auto _new_src = ptr(src->choice.selectAlternateAccess);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "selectAlternateAccess");
        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = ptr(src->accessSelection);
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {
            static const auto type =
                get_field_type<RecordType>(container, "accessSelection");
            const auto container = make_intrusive<RecordVal>(type);

            if (src->present ==
                AlternateAccessSelection__selectAlternateAccess__accessSelection_PR_component) {
              const auto _new_src = ptr(src->choice.component);
              const auto src = _new_src;
              const auto res = convert(src);
              container->AssignField("component", res);
            }

            if (src->present ==
                AlternateAccessSelection__selectAlternateAccess__accessSelection_PR_index) {
              const auto _new_src = ptr(src->choice.index);
              const auto src = _new_src;
              const auto res = convert(src);
              container->AssignField("index", res);
            }

            if (src->present ==
                AlternateAccessSelection__selectAlternateAccess__accessSelection_PR_indexRange) {
              const auto _new_src = ptr(src->choice.indexRange);
              const auto src = _new_src;

              IntrusivePtr<Val> res;
              {
                static const auto type =
                    get_field_type<RecordType>(container, "indexRange");
                const auto container = make_intrusive<RecordVal>(type);

                {
                  const auto _new_src = ptr(src->lowIndex);
                  const auto src = _new_src;
                  const auto res = convert(src);
                  container->AssignField("lowIndex", res);
                }

                {
                  const auto _new_src = ptr(src->numberOfElements);
                  const auto src = _new_src;
                  const auto res = convert(src);
                  container->AssignField("numberOfElements", res);
                }

                res = container;
              }

              container->AssignField("indexRange", res);
            }

            if (src->present ==
                AlternateAccessSelection__selectAlternateAccess__accessSelection_PR_allElements) {
              const auto _new_src = ptr(src->choice.allElements);
              const auto src = _new_src;
              const auto res = true;
              container->AssignField("allElements", res);
            }

            res = container;
          }

          container->AssignField("accessSelection", res);
        }

        {
          const auto _new_src = ptr(src->alternateAccess);
          const auto src = _new_src;
          const auto res = process_AlternateAccess(src);
          container->AssignField("alternateAccess", res);
        }

        res = container;
      }

      container->AssignField("selectAlternateAccess", res);
    }

    if (src->present == AlternateAccessSelection_PR_selectAccess) {
      const auto _new_src = ptr(src->choice.selectAccess);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "selectAccess");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present ==
            AlternateAccessSelection__selectAccess_PR_component) {
          const auto _new_src = ptr(src->choice.component);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("component", res);
        }

        if (src->present == AlternateAccessSelection__selectAccess_PR_index) {
          const auto _new_src = ptr(src->choice.index);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("index", res);
        }

        if (src->present ==
            AlternateAccessSelection__selectAccess_PR_indexRange) {
          const auto _new_src = ptr(src->choice.indexRange);
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {
            static const auto type =
                get_field_type<RecordType>(container, "indexRange");
            const auto container = make_intrusive<RecordVal>(type);

            {
              const auto _new_src = ptr(src->lowIndex);
              const auto src = _new_src;
              const auto res = convert(src);
              container->AssignField("lowIndex", res);
            }

            {
              const auto _new_src = ptr(src->nmberOfElements);
              const auto src = _new_src;
              const auto res = convert(src);
              container->AssignField("nmberOfElements", res);
            }

            res = container;
          }

          container->AssignField("indexRange", res);
        }

        if (src->present ==
            AlternateAccessSelection__selectAccess_PR_allElements) {
          const auto _new_src = ptr(src->choice.allElements);
          const auto src = _new_src;
          const auto res = true;
          container->AssignField("allElements", res);
        }

        res = container;
      }

      container->AssignField("selectAccess", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Read_Request(const Read_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Read_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const std::remove_pointer<decltype(src->specificationWithResult)>::type
          default_value = 0;
      const auto _new_src =
          ptr(src->specificationWithResult ? src->specificationWithResult
                                           : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("specificationWithResult", res);
    }

    {
      const auto _new_src = ptr(src->variableAccessSpecificatn);
      const auto src = _new_src;
      const auto res = process_VariableAccessSpecification(src);
      container->AssignField("variableAccessSpecificatn", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Read_Response(const Read_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Read_Response");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->variableAccessSpecificatn) {
      const auto _new_src = ptr(src->variableAccessSpecificatn);
      const auto src = _new_src;
      const auto res = process_VariableAccessSpecification(src);
      container->AssignField("variableAccessSpecificatn", res);
    }

    {
      const auto _new_src = ptr(src->listOfAccessResult);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfAccessResult");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_AccessResult(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfAccessResult", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Write_Request(const Write_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Write_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->variableAccessSpecificatn);
      const auto src = _new_src;
      const auto res = process_VariableAccessSpecification(src);
      container->AssignField("variableAccessSpecificatn", res);
    }

    {
      const auto _new_src = ptr(src->listOfData);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfData");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_Data(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfData", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Write_Response(const Write_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<VectorType>("mms::Write_Response");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type = get_field_type<RecordType>(container);
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present == Write_Response__Member_PR_failure) {
          const auto _new_src = ptr(src->choice.failure);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("failure", res);
        }

        if (src->present == Write_Response__Member_PR_success) {
          const auto _new_src = ptr(src->choice.success);
          const auto src = _new_src;
          const auto res = true;
          container->AssignField("success", res);
        }

        res = container;
      }

      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_InformationReport(const InformationReport_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::InformationReport");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->variableAccessSpecification);
      const auto src = _new_src;
      const auto res = process_VariableAccessSpecification(src);
      container->AssignField("variableAccessSpecification", res);
    }

    {
      const auto _new_src = ptr(src->listOfAccessResult);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfAccessResult");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_AccessResult(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfAccessResult", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_GetVariableAccessAttributes_Request(
    const GetVariableAccessAttributes_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetVariableAccessAttributes_Request");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == GetVariableAccessAttributes_Request_PR_name) {
      const auto _new_src = ptr(src->choice.name);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("name", res);
    }

    if (src->present == GetVariableAccessAttributes_Request_PR_address) {
      const auto _new_src = ptr(src->choice.address);
      const auto src = _new_src;
      const auto res = process_Address(src);
      container->AssignField("address", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_GetVariableAccessAttributes_Response(
    const GetVariableAccessAttributes_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetVariableAccessAttributes_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->mmsDeletable);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mmsDeletable", res);
    }

    if (src->address) {
      const auto _new_src = ptr(src->address);
      const auto src = _new_src;
      const auto res = process_Address(src);
      container->AssignField("address", res);
    }

    {
      const auto _new_src = ptr(src->typeSpecification);
      const auto src = _new_src;
      const auto res = process_TypeSpecification(src);
      container->AssignField("typeSpecification", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_DefineNamedVariable_Request(const DefineNamedVariable_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DefineNamedVariable_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->variableName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("variableName", res);
    }

    {
      const auto _new_src = ptr(src->address);
      const auto src = _new_src;
      const auto res = process_Address(src);
      container->AssignField("address", res);
    }

    if (src->typeSpecification) {
      const auto _new_src = ptr(src->typeSpecification);
      const auto src = _new_src;
      const auto res = process_TypeSpecification(src);
      container->AssignField("typeSpecification", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_DefineScatteredAccess_Request(
    const DefineScatteredAccess_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DefineScatteredAccess_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->scatteredAccessName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("scatteredAccessName", res);
    }

    {
      const auto _new_src = ptr(src->scatteredAccessDescription);
      const auto src = _new_src;
      const auto res = process_ScatteredAccessDescription(src);
      container->AssignField("scatteredAccessDescription", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_GetScatteredAccessAttributes_Request(
    const GetScatteredAccessAttributes_Request_t *src) {
  const auto res = process_ObjectName(src);
  return res;
}

IntrusivePtr<Val> process_GetScatteredAccessAttributes_Response(
    const GetScatteredAccessAttributes_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetScatteredAccessAttributes_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->mmsDeletable);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mmsDeletable", res);
    }

    {
      const auto _new_src = ptr(src->scatteredAccessDescription);
      const auto src = _new_src;
      const auto res = process_ScatteredAccessDescription(src);
      container->AssignField("scatteredAccessDescription", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_DeleteVariableAccess_Request(
    const DeleteVariableAccess_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DeleteVariableAccess_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->scopeOfDelete);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("scopeOfDelete", res);
    }

    if (src->listOfName) {
      const auto _new_src = ptr(src->listOfName);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfName");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_ObjectName(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfName", res);
    }

    if (src->domainName) {
      const auto _new_src = ptr(src->domainName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("domainName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_DeleteVariableAccess_Response(
    const DeleteVariableAccess_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DeleteVariableAccess_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->numberMatched);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("numberMatched", res);
    }

    {
      const auto _new_src = ptr(src->numberDeleted);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("numberDeleted", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_DeleteVariableAccess_Error(const DeleteVariableAccess_Error_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_DefineNamedVariableList_Request(
    const DefineNamedVariableList_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DefineNamedVariableList_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->variableListName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("variableListName", res);
    }

    {
      const auto _new_src = ptr(src->listOfVariable);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfVariable");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {
            static const auto type = get_field_type<RecordType>(container);
            const auto container = make_intrusive<RecordVal>(type);

            {
              const auto _new_src = ptr(src->variableSpecification);
              const auto src = _new_src;
              const auto res = process_VariableSpecification(src);
              container->AssignField("variableSpecification", res);
            }

            if (src->alternateAccess) {
              const auto _new_src = ptr(src->alternateAccess);
              const auto src = _new_src;
              const auto res = process_AlternateAccess(src);
              container->AssignField("alternateAccess", res);
            }

            res = container;
          }

          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfVariable", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_GetNamedVariableListAttributes_Request(
    const GetNamedVariableListAttributes_Request_t *src) {
  const auto res = process_ObjectName(src);
  return res;
}

IntrusivePtr<Val> process_GetNamedVariableListAttributes_Response(
    const GetNamedVariableListAttributes_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>(
        "mms::GetNamedVariableListAttributes_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->mmsDeletable);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mmsDeletable", res);
    }

    {
      const auto _new_src = ptr(src->listOfVariable);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfVariable");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {
            static const auto type = get_field_type<RecordType>(container);
            const auto container = make_intrusive<RecordVal>(type);

            {
              const auto _new_src = ptr(src->variableSpecification);
              const auto src = _new_src;
              const auto res = process_VariableSpecification(src);
              container->AssignField("variableSpecification", res);
            }

            if (src->alternateAccess) {
              const auto _new_src = ptr(src->alternateAccess);
              const auto src = _new_src;
              const auto res = process_AlternateAccess(src);
              container->AssignField("alternateAccess", res);
            }

            res = container;
          }

          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfVariable", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_DeleteNamedVariableList_Request(
    const DeleteNamedVariableList_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DeleteNamedVariableList_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->scopeOfDelete);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("scopeOfDelete", res);
    }

    if (src->listOfVariableListName) {
      const auto _new_src = ptr(src->listOfVariableListName);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfVariableListName");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_ObjectName(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfVariableListName", res);
    }

    if (src->domainName) {
      const auto _new_src = ptr(src->domainName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("domainName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_DeleteNamedVariableList_Response(
    const DeleteNamedVariableList_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DeleteNamedVariableList_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->numberMatched);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("numberMatched", res);
    }

    {
      const auto _new_src = ptr(src->numberDeleted);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("numberDeleted", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_DeleteNamedVariableList_Error(
    const DeleteNamedVariableList_Error_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val>
process_DefineNamedType_Request(const DefineNamedType_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DefineNamedType_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->typeName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("typeName", res);
    }

    {
      const auto _new_src = ptr(src->typeSpecification);
      const auto src = _new_src;
      const auto res = process_TypeSpecification(src);
      container->AssignField("typeSpecification", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_GetNamedTypeAttributes_Request(
    const GetNamedTypeAttributes_Request_t *src) {
  const auto res = process_ObjectName(src);
  return res;
}

IntrusivePtr<Val> process_GetNamedTypeAttributes_Response(
    const GetNamedTypeAttributes_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetNamedTypeAttributes_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->mmsDeletable);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mmsDeletable", res);
    }

    {
      const auto _new_src = ptr(src->typeSpecification);
      const auto src = _new_src;
      const auto res = process_TypeSpecification(src);
      container->AssignField("typeSpecification", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_DeleteNamedType_Request(const DeleteNamedType_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DeleteNamedType_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->scopeOfDelete);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("scopeOfDelete", res);
    }

    if (src->listOfTypeName) {
      const auto _new_src = ptr(src->listOfTypeName);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfTypeName");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_ObjectName(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfTypeName", res);
    }

    if (src->domainName) {
      const auto _new_src = ptr(src->domainName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("domainName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_DeleteNamedType_Response(const DeleteNamedType_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DeleteNamedType_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->numberMatched);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("numberMatched", res);
    }

    {
      const auto _new_src = ptr(src->numberDeleted);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("numberDeleted", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_DeleteNamedType_Error(const DeleteNamedType_Error_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_AccessResult(const AccessResult_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::AccessResult");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == AccessResult_PR_failure) {
      const auto _new_src = ptr(src->choice.failure);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("failure", res);
    }

    if (src->present == AccessResult_PR_success) {
      const auto _new_src = ptr(src->choice.success);
      const auto src = _new_src;
      const auto res = process_Data(src);
      container->AssignField("success", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Data(const Data_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Data");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == Data_PR_array) {
      const auto _new_src = ptr(src->choice.array);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type = get_field_type<VectorType>(container, "array");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_Data(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("array", res);
    }

    if (src->present == Data_PR_structure) {
      const auto _new_src = ptr(src->choice.structure);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "structure");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_Data(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("structure", res);
    }

    if (src->present == Data_PR_boolean) {
      const auto _new_src = ptr(src->choice.boolean);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("boolean", res);
    }

    if (src->present == Data_PR_bit_string) {
      const auto _new_src = ptr(src->choice.bit_string);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("bit_string", res);
    }

    if (src->present == Data_PR_integer) {
      const auto _new_src = ptr(src->choice.integer);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("integer", res);
    }

    if (src->present == Data_PR_unsigned) {
      const auto _new_src = ptr(src->choice.Unsigned);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("unsigned", res);
    }

    if (src->present == Data_PR_floating_point) {
      const auto _new_src = ptr(src->choice.floating_point);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("floating_point", res);
    }

    if (src->present == Data_PR_octet_string) {
      const auto _new_src = ptr(src->choice.octet_string);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("octet_string", res);
    }

    if (src->present == Data_PR_visible_string) {
      const auto _new_src = ptr(src->choice.visible_string);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("visible_string", res);
    }

    if (src->present == Data_PR_binary_time) {
      const auto _new_src = ptr(src->choice.binary_time);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("binary_time", res);
    }

    if (src->present == Data_PR_bcd) {
      const auto _new_src = ptr(src->choice.bcd);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("bcd", res);
    }

    if (src->present == Data_PR_booleanArray) {
      const auto _new_src = ptr(src->choice.booleanArray);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("booleanArray", res);
    }

    if (src->present == Data_PR_objId) {
      const auto _new_src = ptr(src->choice.objId);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("objId", res);
    }

    if (src->present == Data_PR_mMSString) {
      const auto _new_src = ptr(src->choice.mMSString);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mMSString", res);
    }

    if (src->present == Data_PR_utc_time) {
      const auto _new_src = ptr(src->choice.utc_time);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("utc_time", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_VariableAccessSpecification(const VariableAccessSpecification_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::VariableAccessSpecification");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == VariableAccessSpecification_PR_listOfVariable) {
      const auto _new_src = ptr(src->choice.listOfVariable);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfVariable");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {
            static const auto type = get_field_type<RecordType>(container);
            const auto container = make_intrusive<RecordVal>(type);

            {
              const auto _new_src = ptr(src->variableSpecification);
              const auto src = _new_src;
              const auto res = process_VariableSpecification(src);
              container->AssignField("variableSpecification", res);
            }

            if (src->alternateAccess) {
              const auto _new_src = ptr(src->alternateAccess);
              const auto src = _new_src;
              const auto res = process_AlternateAccess(src);
              container->AssignField("alternateAccess", res);
            }

            res = container;
          }

          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfVariable", res);
    }

    if (src->present == VariableAccessSpecification_PR_variableListName) {
      const auto _new_src = ptr(src->choice.variableListName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("variableListName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_ScatteredAccessDescription(const ScatteredAccessDescription_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<VectorType>("mms::ScatteredAccessDescription");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type = get_field_type<RecordType>(container);
        const auto container = make_intrusive<RecordVal>(type);

        if (src->componentName) {
          const auto _new_src = ptr(src->componentName);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("componentName", res);
        }

        {
          const auto _new_src = ptr(src->variableSpecification);
          const auto src = _new_src;
          const auto res = process_VariableSpecification(src);
          container->AssignField("variableSpecification", res);
        }

        if (src->alternateAccess) {
          const auto _new_src = ptr(src->alternateAccess);
          const auto src = _new_src;
          const auto res = process_AlternateAccess(src);
          container->AssignField("alternateAccess", res);
        }

        res = container;
      }

      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_VariableSpecification(const VariableSpecification_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::VariableSpecification");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == VariableSpecification_PR_name) {
      const auto _new_src = ptr(src->choice.name);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("name", res);
    }

    if (src->present == VariableSpecification_PR_address) {
      const auto _new_src = ptr(src->choice.address);
      const auto src = _new_src;
      const auto res = process_Address(src);
      container->AssignField("address", res);
    }

    if (src->present == VariableSpecification_PR_variableDescription) {
      const auto _new_src = ptr(src->choice.variableDescription);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "variableDescription");
        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = ptr(src->address);
          const auto src = _new_src;
          const auto res = process_Address(src);
          container->AssignField("address", res);
        }

        {
          const auto _new_src = ptr(src->typeSpecification);
          const auto src = _new_src;
          const auto res = process_TypeSpecification(src);
          container->AssignField("typeSpecification", res);
        }

        res = container;
      }

      container->AssignField("variableDescription", res);
    }

    if (src->present == VariableSpecification_PR_scatteredAccessDescription) {
      const auto _new_src = ptr(src->choice.scatteredAccessDescription);
      const auto src = _new_src;
      const auto res = process_ScatteredAccessDescription(src);
      container->AssignField("scatteredAccessDescription", res);
    }

    if (src->present == VariableSpecification_PR_invalidated) {
      const auto _new_src = ptr(src->choice.invalidated);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("invalidated", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Address(const Address_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Address");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == Address_PR_numericAddress) {
      const auto _new_src = ptr(src->choice.numericAddress);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("numericAddress", res);
    }

    if (src->present == Address_PR_symbolicAddress) {
      const auto _new_src = ptr(src->choice.symbolicAddress);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("symbolicAddress", res);
    }

    if (src->present == Address_PR_unconstrainedAddress) {
      const auto _new_src = ptr(src->choice.unconstrainedAddress);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("unconstrainedAddress", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_TakeControl_Request(const TakeControl_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::TakeControl_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->semaphoreName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("semaphoreName", res);
    }

    if (src->namedToken) {
      const auto _new_src = ptr(src->namedToken);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("namedToken", res);
    }

    {
      const std::remove_pointer<decltype(src->priority)>::type default_value =
          64;
      const auto _new_src = ptr(src->priority ? src->priority : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("priority", res);
    }

    if (src->acceptableDelay) {
      const auto _new_src = ptr(src->acceptableDelay);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("acceptableDelay", res);
    }

    if (src->controlTimeOut) {
      const auto _new_src = ptr(src->controlTimeOut);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("controlTimeOut", res);
    }

    if (src->abortOnTimeOut) {
      const auto _new_src = ptr(src->abortOnTimeOut);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("abortOnTimeOut", res);
    }

    {
      const std::remove_pointer<decltype(src->relinquishIfConnectionLost)>::type
          default_value = 1;
      const auto _new_src =
          ptr(src->relinquishIfConnectionLost ? src->relinquishIfConnectionLost
                                              : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("relinquishIfConnectionLost", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_TakeControl_Response(const TakeControl_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::TakeControl_Response");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == TakeControl_Response_PR_noResult) {
      const auto _new_src = ptr(src->choice.noResult);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("noResult", res);
    }

    if (src->present == TakeControl_Response_PR_namedToken) {
      const auto _new_src = ptr(src->choice.namedToken);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("namedToken", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_RelinquishControl_Request(const RelinquishControl_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::RelinquishControl_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->semaphoreName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("semaphoreName", res);
    }

    if (src->namedToken) {
      const auto _new_src = ptr(src->namedToken);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("namedToken", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_DefineSemaphore_Request(const DefineSemaphore_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DefineSemaphore_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->semaphoreName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("semaphoreName", res);
    }

    {
      const auto _new_src = ptr(src->numbersOfTokens);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("numbersOfTokens", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_DeleteSemaphore_Request(const DeleteSemaphore_Request_t *src) {
  const auto res = process_ObjectName(src);
  return res;
}

IntrusivePtr<Val> process_ReportSemaphoreStatus_Request(
    const ReportSemaphoreStatus_Request_t *src) {
  const auto res = process_ObjectName(src);
  return res;
}

IntrusivePtr<Val> process_ReportSemaphoreStatus_Response(
    const ReportSemaphoreStatus_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ReportSemaphoreStatus_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->mmsDeletable);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mmsDeletable", res);
    }

    {
      const auto _new_src = ptr(src->Class);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("class", res);
    }

    {
      const auto _new_src = ptr(src->numberOfTokens);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("numberOfTokens", res);
    }

    {
      const auto _new_src = ptr(src->numberOfOwnedTokens);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("numberOfOwnedTokens", res);
    }

    {
      const auto _new_src = ptr(src->numberOfHungTokens);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("numberOfHungTokens", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ReportPoolSemaphoreStatus_Request(
    const ReportPoolSemaphoreStatus_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ReportPoolSemaphoreStatus_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->semaphoreName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("semaphoreName", res);
    }

    if (src->nameToStartAfter) {
      const auto _new_src = ptr(src->nameToStartAfter);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("nameToStartAfter", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ReportPoolSemaphoreStatus_Response(
    const ReportPoolSemaphoreStatus_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ReportPoolSemaphoreStatus_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->listOfNamedTokens);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfNamedTokens");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {
            static const auto type = get_field_type<RecordType>(container);
            const auto container = make_intrusive<RecordVal>(type);

            if (src->present ==
                ReportPoolSemaphoreStatus_Response__listOfNamedTokens__Member_PR_freeNamedToken) {
              const auto _new_src = ptr(src->choice.freeNamedToken);
              const auto src = _new_src;
              const auto res = convert(src);
              container->AssignField("freeNamedToken", res);
            }

            if (src->present ==
                ReportPoolSemaphoreStatus_Response__listOfNamedTokens__Member_PR_ownedNamedToken) {
              const auto _new_src = ptr(src->choice.ownedNamedToken);
              const auto src = _new_src;
              const auto res = convert(src);
              container->AssignField("ownedNamedToken", res);
            }

            if (src->present ==
                ReportPoolSemaphoreStatus_Response__listOfNamedTokens__Member_PR_hungNamedToken) {
              const auto _new_src = ptr(src->choice.hungNamedToken);
              const auto src = _new_src;
              const auto res = convert(src);
              container->AssignField("hungNamedToken", res);
            }

            res = container;
          }

          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfNamedTokens", res);
    }

    {
      const std::remove_pointer<decltype(src->moreFollows)>::type
          default_value = 1;
      const auto _new_src =
          ptr(src->moreFollows ? src->moreFollows : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("moreFollows", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ReportSemaphoreEntryStatus_Request(
    const ReportSemaphoreEntryStatus_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ReportSemaphoreEntryStatus_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->semaphoreName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("semaphoreName", res);
    }

    {
      const auto _new_src = ptr(src->state);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("state", res);
    }

    if (src->entryIdToStartAfter) {
      const auto _new_src = ptr(src->entryIdToStartAfter);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("entryIdToStartAfter", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ReportSemaphoreEntryStatus_Response(
    const ReportSemaphoreEntryStatus_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ReportSemaphoreEntryStatus_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->listOfSemaphoreEntry);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfSemaphoreEntry");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_SemaphoreEntry(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfSemaphoreEntry", res);
    }

    {
      const std::remove_pointer<decltype(src->moreFollows)>::type
          default_value = 1;
      const auto _new_src =
          ptr(src->moreFollows ? src->moreFollows : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("moreFollows", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_AttachToSemaphore(const AttachToSemaphore_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::AttachToSemaphore");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->semaphoreName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("semaphoreName", res);
    }

    if (src->namedToken) {
      const auto _new_src = ptr(src->namedToken);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("namedToken", res);
    }

    {
      const std::remove_pointer<decltype(src->priority)>::type default_value =
          64;
      const auto _new_src = ptr(src->priority ? src->priority : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("priority", res);
    }

    if (src->acceptableDelay) {
      const auto _new_src = ptr(src->acceptableDelay);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("acceptableDelay", res);
    }

    if (src->controlTimeOut) {
      const auto _new_src = ptr(src->controlTimeOut);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("controlTimeOut", res);
    }

    if (src->abortOnTimeOut) {
      const auto _new_src = ptr(src->abortOnTimeOut);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("abortOnTimeOut", res);
    }

    {
      const std::remove_pointer<decltype(src->relinquishIfConnectionLost)>::type
          default_value = 1;
      const auto _new_src =
          ptr(src->relinquishIfConnectionLost ? src->relinquishIfConnectionLost
                                              : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("relinquishIfConnectionLost", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_SemaphoreEntry(const SemaphoreEntry_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::SemaphoreEntry");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->entryId);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("entryId", res);
    }

    {
      const auto _new_src = ptr(src->entryClass);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("entryClass", res);
    }

    if (src->namedToken) {
      const auto _new_src = ptr(src->namedToken);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("namedToken", res);
    }

    {
      const std::remove_pointer<decltype(src->priority)>::type default_value =
          64;
      const auto _new_src = ptr(src->priority ? src->priority : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("priority", res);
    }

    if (src->remainingTimeOut) {
      const auto _new_src = ptr(src->remainingTimeOut);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("remainingTimeOut", res);
    }

    if (src->abortOnTimeOut) {
      const auto _new_src = ptr(src->abortOnTimeOut);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("abortOnTimeOut", res);
    }

    {
      const std::remove_pointer<decltype(src->relinquishIfConnectionLost)>::type
          default_value = 1;
      const auto _new_src =
          ptr(src->relinquishIfConnectionLost ? src->relinquishIfConnectionLost
                                              : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("relinquishIfConnectionLost", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Input_Request(const Input_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Input_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->operatorStationName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("operatorStationName", res);
    }

    {
      const std::remove_pointer<decltype(src->echo)>::type default_value = 1;
      const auto _new_src = ptr(src->echo ? src->echo : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("echo", res);
    }

    if (src->listOfPromptData) {
      const auto _new_src = ptr(src->listOfPromptData);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfPromptData");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = convert(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfPromptData", res);
    }

    if (src->inputTimeOut) {
      const auto _new_src = ptr(src->inputTimeOut);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("inputTimeOut", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Output_Request(const Output_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Output_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->operatorStationName);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("operatorStationName", res);
    }

    {
      const auto _new_src = ptr(src->listOfOutputData);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfOutputData");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = convert(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfOutputData", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_DefineEventCondition_Request(
    const DefineEventCondition_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DefineEventCondition_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->eventConditionName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventConditionName", res);
    }

    {
      const auto _new_src = ptr(src->Class);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("class", res);
    }

    {
      const std::remove_pointer<decltype(src->prio_rity)>::type default_value =
          64;
      const auto _new_src =
          ptr(src->prio_rity ? src->prio_rity : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("prio_rity", res);
    }

    {
      const std::remove_pointer<decltype(src->severity)>::type default_value =
          64;
      const auto _new_src = ptr(src->severity ? src->severity : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("severity", res);
    }

    if (src->alarmSummaryReports) {
      const auto _new_src = ptr(src->alarmSummaryReports);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("alarmSummaryReports", res);
    }

    if (src->monitoredVariable) {
      const auto _new_src = ptr(src->monitoredVariable);
      const auto src = _new_src;
      const auto res = process_VariableSpecification(src);
      container->AssignField("monitoredVariable", res);
    }

    if (src->evaluationInterval) {
      const auto _new_src = ptr(src->evaluationInterval);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("evaluationInterval", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_DeleteEventCondition_Request(
    const DeleteEventCondition_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DeleteEventCondition_Request");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == DeleteEventCondition_Request_PR_specific) {
      const auto _new_src = ptr(src->choice.specific);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "specific");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_ObjectName(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("specific", res);
    }

    if (src->present == DeleteEventCondition_Request_PR_aa_specific) {
      const auto _new_src = ptr(src->choice.aa_specific);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("aa_specific", res);
    }

    if (src->present == DeleteEventCondition_Request_PR_domain) {
      const auto _new_src = ptr(src->choice.domain);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("_domain", res);
    }

    if (src->present == DeleteEventCondition_Request_PR_vmd) {
      const auto _new_src = ptr(src->choice.vmd);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("vmd", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_DeleteEventCondition_Response(
    const DeleteEventCondition_Response_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_GetEventConditionAttributes_Request(
    const GetEventConditionAttributes_Request_t *src) {
  const auto res = process_ObjectName(src);
  return res;
}

IntrusivePtr<Val> process_GetEventConditionAttributes_Response(
    const GetEventConditionAttributes_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetEventConditionAttributes_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const std::remove_pointer<decltype(src->mmsDeletable)>::type
          default_value = 0;
      const auto _new_src =
          ptr(src->mmsDeletable ? src->mmsDeletable : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mmsDeletable", res);
    }

    {
      const auto _new_src = ptr(src->Class);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("class", res);
    }

    {
      const std::remove_pointer<decltype(src->prio_rity)>::type default_value =
          64;
      const auto _new_src =
          ptr(src->prio_rity ? src->prio_rity : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("prio_rity", res);
    }

    {
      const std::remove_pointer<decltype(src->severity)>::type default_value =
          64;
      const auto _new_src = ptr(src->severity ? src->severity : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("severity", res);
    }

    {
      const std::remove_pointer<decltype(src->alarmSummaryReports)>::type
          default_value = 0;
      const auto _new_src = ptr(
          src->alarmSummaryReports ? src->alarmSummaryReports : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("alarmSummaryReports", res);
    }

    if (src->monitoredVariable) {
      const auto _new_src = ptr(src->monitoredVariable);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "monitoredVariable");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present ==
            GetEventConditionAttributes_Response__monitoredVariable_PR_variableReference) {
          const auto _new_src = ptr(src->choice.variableReference);
          const auto src = _new_src;
          const auto res = process_VariableSpecification(src);
          container->AssignField("variableReference", res);
        }

        if (src->present ==
            GetEventConditionAttributes_Response__monitoredVariable_PR_undefined) {
          const auto _new_src = ptr(src->choice.undefined);
          const auto src = _new_src;
          const auto res = true;
          container->AssignField("undefined", res);
        }

        res = container;
      }

      container->AssignField("monitoredVariable", res);
    }

    if (src->evaluationInterval) {
      const auto _new_src = ptr(src->evaluationInterval);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("evaluationInterval", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ReportEventConditionStatus_Request(
    const ReportEventConditionStatus_Request_t *src) {
  const auto res = process_ObjectName(src);
  return res;
}

IntrusivePtr<Val> process_ReportEventConditionStatus_Response(
    const ReportEventConditionStatus_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ReportEventConditionStatus_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->currentState);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("currentState", res);
    }

    {
      const auto _new_src = ptr(src->numberOfEventEnrollments);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("numberOfEventEnrollments", res);
    }

    if (src->enabled) {
      const auto _new_src = ptr(src->enabled);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("enabled", res);
    }

    if (src->timeOfLastTransitionToActive) {
      const auto _new_src = ptr(src->timeOfLastTransitionToActive);
      const auto src = _new_src;
      const auto res = process_EventTime(src);
      container->AssignField("timeOfLastTransitionToActive", res);
    }

    if (src->timeOfLastTransitionToIdle) {
      const auto _new_src = ptr(src->timeOfLastTransitionToIdle);
      const auto src = _new_src;
      const auto res = process_EventTime(src);
      container->AssignField("timeOfLastTransitionToIdle", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_AlterEventConditionMonitoring_Request(
    const AlterEventConditionMonitoring_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::AlterEventConditionMonitoring_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->eventConditionName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventConditionName", res);
    }

    if (src->enabled) {
      const auto _new_src = ptr(src->enabled);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("enabled", res);
    }

    if (src->priority) {
      const auto _new_src = ptr(src->priority);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("priority", res);
    }

    if (src->alarmSummaryReports) {
      const auto _new_src = ptr(src->alarmSummaryReports);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("alarmSummaryReports", res);
    }

    if (src->evaluationInterval) {
      const auto _new_src = ptr(src->evaluationInterval);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("evaluationInterval", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_TriggerEvent_Request(const TriggerEvent_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::TriggerEvent_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->eventConditionName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventConditionName", res);
    }

    if (src->priority) {
      const auto _new_src = ptr(src->priority);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("priority", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_DefineEventAction_Request(const DefineEventAction_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DefineEventAction_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->eventActionName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventActionName", res);
    }

    if (src->listOfModifier) {
      const auto _new_src = ptr(src->listOfModifier);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfModifier");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_Modifier(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfModifier", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_DeleteEventAction_Request(const DeleteEventAction_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DeleteEventAction_Request");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == DeleteEventAction_Request_PR_specific) {
      const auto _new_src = ptr(src->choice.specific);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "specific");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_ObjectName(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("specific", res);
    }

    if (src->present == DeleteEventAction_Request_PR_aa_specific) {
      const auto _new_src = ptr(src->choice.aa_specific);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("aa_specific", res);
    }

    if (src->present == DeleteEventAction_Request_PR_domain) {
      const auto _new_src = ptr(src->choice.domain);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("_domain", res);
    }

    if (src->present == DeleteEventAction_Request_PR_vmd) {
      const auto _new_src = ptr(src->choice.vmd);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("vmd", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_DeleteEventAction_Response(const DeleteEventAction_Response_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_GetEventActionAttributes_Request(
    const GetEventActionAttributes_Request_t *src) {
  const auto res = process_ObjectName(src);
  return res;
}

IntrusivePtr<Val> process_GetEventActionAttributes_Response(
    const GetEventActionAttributes_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetEventActionAttributes_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const std::remove_pointer<decltype(src->mmsDeletable)>::type
          default_value = 0;
      const auto _new_src =
          ptr(src->mmsDeletable ? src->mmsDeletable : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mmsDeletable", res);
    }

    {
      const auto _new_src = ptr(src->listOfModifier);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfModifier");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_Modifier(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfModifier", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ReportEventActionStatus_Request(
    const ReportEventActionStatus_Request_t *src) {
  const auto res = process_ObjectName(src);
  return res;
}

IntrusivePtr<Val> process_ReportEventActionStatus_Response(
    const ReportEventActionStatus_Response_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_DefineEventEnrollment_Request(
    const DefineEventEnrollment_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DefineEventEnrollment_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->eventEnrollmentName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventEnrollmentName", res);
    }

    {
      const auto _new_src = ptr(src->eventConditionName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventConditionName", res);
    }

    {
      const auto _new_src = ptr(src->eventConditionTransition);
      const auto src = _new_src;
      const auto res = process_Transitions(src);
      container->AssignField("eventConditionTransition", res);
    }

    {
      const auto _new_src = ptr(src->alarmAcknowledgementRule);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("alarmAcknowledgementRule", res);
    }

    if (src->eventActionName) {
      const auto _new_src = ptr(src->eventActionName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventActionName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_DefineEventEnrollment_Error(const DefineEventEnrollment_Error_t *src) {
  const auto res = process_ObjectName(src);
  return res;
}

IntrusivePtr<Val> process_DeleteEventEnrollment_Request(
    const DeleteEventEnrollment_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DeleteEventEnrollment_Request");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == DeleteEventEnrollment_Request_PR_specific) {
      const auto _new_src = ptr(src->choice.specific);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "specific");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_ObjectName(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("specific", res);
    }

    if (src->present == DeleteEventEnrollment_Request_PR_ec) {
      const auto _new_src = ptr(src->choice.ec);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("ec", res);
    }

    if (src->present == DeleteEventEnrollment_Request_PR_ea) {
      const auto _new_src = ptr(src->choice.ea);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("ea", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_DeleteEventEnrollment_Response(
    const DeleteEventEnrollment_Response_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_GetEventEnrollmentAttributes_Request(
    const GetEventEnrollmentAttributes_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetEventEnrollmentAttributes_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const std::remove_pointer<decltype(src->scopeOfRequest)>::type
          default_value = 1;
      const auto _new_src =
          ptr(src->scopeOfRequest ? src->scopeOfRequest : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("scopeOfRequest", res);
    }

    if (src->eventEnrollmentNames) {
      const auto _new_src = ptr(src->eventEnrollmentNames);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "eventEnrollmentNames");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_ObjectName(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("eventEnrollmentNames", res);
    }

    if (src->eventConditionName) {
      const auto _new_src = ptr(src->eventConditionName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventConditionName", res);
    }

    if (src->eventActionName) {
      const auto _new_src = ptr(src->eventActionName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventActionName", res);
    }

    if (src->continueAfter) {
      const auto _new_src = ptr(src->continueAfter);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("continueAfter", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_EventEnrollment(const EventEnrollment_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::EventEnrollment");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->eventEnrollmentName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventEnrollmentName", res);
    }

    {
      const auto _new_src = ptr(src->eventConditionName);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "eventConditionName");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present ==
            EventEnrollment__eventConditionName_PR_eventCondition) {
          const auto _new_src = ptr(src->choice.eventCondition);
          const auto src = _new_src;
          const auto res = process_ObjectName(src);
          container->AssignField("eventCondition", res);
        }

        if (src->present == EventEnrollment__eventConditionName_PR_undefined) {
          const auto _new_src = ptr(src->choice.undefined);
          const auto src = _new_src;
          const auto res = true;
          container->AssignField("undefined", res);
        }

        res = container;
      }

      container->AssignField("eventConditionName", res);
    }

    if (src->eventActionName) {
      const auto _new_src = ptr(src->eventActionName);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "eventActionName");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present == EventEnrollment__eventActionName_PR_eventAction) {
          const auto _new_src = ptr(src->choice.eventAction);
          const auto src = _new_src;
          const auto res = process_ObjectName(src);
          container->AssignField("eventAction", res);
        }

        if (src->present == EventEnrollment__eventActionName_PR_undefined) {
          const auto _new_src = ptr(src->choice.undefined);
          const auto src = _new_src;
          const auto res = true;
          container->AssignField("undefined", res);
        }

        res = container;
      }

      container->AssignField("eventActionName", res);
    }

    {
      const std::remove_pointer<decltype(src->mmsDeletable)>::type
          default_value = 0;
      const auto _new_src =
          ptr(src->mmsDeletable ? src->mmsDeletable : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mmsDeletable", res);
    }

    {
      const auto _new_src = ptr(src->enrollmentClass);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("enrollmentClass", res);
    }

    {
      const auto _new_src = ptr(src->duration);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("duration", res);
    }

    {
      const auto _new_src = ptr(src->invokeID);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("invokeID", res);
    }

    if (src->remainingAcceptableDelay) {
      const auto _new_src = ptr(src->remainingAcceptableDelay);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("remainingAcceptableDelay", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_GetEventEnrollmentAttributes_Response(
    const GetEventEnrollmentAttributes_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetEventEnrollmentAttributes_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->listOfEventEnrollment);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfEventEnrollment");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_EventEnrollment(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfEventEnrollment", res);
    }

    {
      const std::remove_pointer<decltype(src->moreFollows)>::type
          default_value = 0;
      const auto _new_src =
          ptr(src->moreFollows ? src->moreFollows : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("moreFollows", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ReportEventEnrollmentStatus_Request(
    const ReportEventEnrollmentStatus_Request_t *src) {
  const auto res = process_ObjectName(src);
  return res;
}

IntrusivePtr<Val> process_ReportEventEnrollmentStatus_Response(
    const ReportEventEnrollmentStatus_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ReportEventEnrollmentStatus_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->eventConditionTransitions);
      const auto src = _new_src;
      const auto res = process_Transitions(src);
      container->AssignField("eventConditionTransitions", res);
    }

    {
      const std::remove_pointer<decltype(src->notificationLost)>::type
          default_value = 0;
      const auto _new_src =
          ptr(src->notificationLost ? src->notificationLost : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("notificationLost", res);
    }

    {
      const auto _new_src = ptr(src->duration);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("duration", res);
    }

    if (src->alarmAcknowledgmentRule) {
      const auto _new_src = ptr(src->alarmAcknowledgmentRule);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("alarmAcknowledgmentRule", res);
    }

    {
      const auto _new_src = ptr(src->currentState);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("currentState", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_AlterEventEnrollment_Request(
    const AlterEventEnrollment_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::AlterEventEnrollment_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->eventEnrollmentName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventEnrollmentName", res);
    }

    if (src->eventConditionTransitions) {
      const auto _new_src = ptr(src->eventConditionTransitions);
      const auto src = _new_src;
      const auto res = process_Transitions(src);
      container->AssignField("eventConditionTransitions", res);
    }

    if (src->alarmAcknowledgmentRule) {
      const auto _new_src = ptr(src->alarmAcknowledgmentRule);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("alarmAcknowledgmentRule", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_AlterEventEnrollment_Response(
    const AlterEventEnrollment_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::AlterEventEnrollment_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->currentState);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "currentState");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present ==
            AlterEventEnrollment_Response__currentState_PR_state) {
          const auto _new_src = ptr(src->choice.state);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("state", res);
        }

        if (src->present ==
            AlterEventEnrollment_Response__currentState_PR_undefined) {
          const auto _new_src = ptr(src->choice.undefined);
          const auto src = _new_src;
          const auto res = true;
          container->AssignField("undefined", res);
        }

        res = container;
      }

      container->AssignField("currentState", res);
    }

    {
      const auto _new_src = ptr(src->transitionTime);
      const auto src = _new_src;
      const auto res = process_EventTime(src);
      container->AssignField("transitionTime", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_AcknowledgeEventNotification_Request(
    const AcknowledgeEventNotification_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::AcknowledgeEventNotification_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->eventEnrollmentName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventEnrollmentName", res);
    }

    {
      const auto _new_src = ptr(src->acknowledgedState);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("acknowledgedState", res);
    }

    {
      const auto _new_src = ptr(src->timeOfAcknowledgedTransition);
      const auto src = _new_src;
      const auto res = process_EventTime(src);
      container->AssignField("timeOfAcknowledgedTransition", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_GetAlarmSummary_Request(const GetAlarmSummary_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetAlarmSummary_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const std::remove_pointer<decltype(src->enrollmentsOnly)>::type
          default_value = 1;
      const auto _new_src =
          ptr(src->enrollmentsOnly ? src->enrollmentsOnly : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("enrollmentsOnly", res);
    }

    {
      const std::remove_pointer<decltype(src->activeAlarmsOnly)>::type
          default_value = 1;
      const auto _new_src =
          ptr(src->activeAlarmsOnly ? src->activeAlarmsOnly : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("activeAlarmsOnly", res);
    }

    {
      const auto _new_src = ptr(src->acknowledgmentFilter);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("acknowledgmentFilter", res);
    }

    if (src->severityFilter) {
      const auto _new_src = ptr(src->severityFilter);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "severityFilter");
        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = ptr(src->mostSevere);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("mostSevere", res);
        }

        {
          const auto _new_src = ptr(src->leastSevere);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("leastSevere", res);
        }

        res = container;
      }

      container->AssignField("severityFilter", res);
    }

    if (src->continueAfter) {
      const auto _new_src = ptr(src->continueAfter);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("continueAfter", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_GetAlarmSummary_Response(const GetAlarmSummary_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetAlarmSummary_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->listOfAlarmSummary);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfAlarmSummary");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_AlarmSummary(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfAlarmSummary", res);
    }

    {
      const std::remove_pointer<decltype(src->moreFollows)>::type
          default_value = 0;
      const auto _new_src =
          ptr(src->moreFollows ? src->moreFollows : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("moreFollows", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_AlarmSummary(const AlarmSummary_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::AlarmSummary");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->eventConditionName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventConditionName", res);
    }

    {
      const auto _new_src = ptr(src->severity);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("severity", res);
    }

    {
      const auto _new_src = ptr(src->currentState);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("currentState", res);
    }

    {
      const auto _new_src = ptr(src->unacknowledgedState);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("unacknowledgedState", res);
    }

    if (src->timeOfLastTransitionToActive) {
      const auto _new_src = ptr(src->timeOfLastTransitionToActive);
      const auto src = _new_src;
      const auto res = process_EventTime(src);
      container->AssignField("timeOfLastTransitionToActive", res);
    }

    if (src->timeOfLastTransitionToIdle) {
      const auto _new_src = ptr(src->timeOfLastTransitionToIdle);
      const auto src = _new_src;
      const auto res = process_EventTime(src);
      container->AssignField("timeOfLastTransitionToIdle", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_GetAlarmEnrollmentSummary_Request(
    const GetAlarmEnrollmentSummary_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetAlarmEnrollmentSummary_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const std::remove_pointer<decltype(src->enrollmentsOnly)>::type
          default_value = 1;
      const auto _new_src =
          ptr(src->enrollmentsOnly ? src->enrollmentsOnly : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("enrollmentsOnly", res);
    }

    {
      const std::remove_pointer<decltype(src->activeAlarmsOnly)>::type
          default_value = 1;
      const auto _new_src =
          ptr(src->activeAlarmsOnly ? src->activeAlarmsOnly : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("activeAlarmsOnly", res);
    }

    {
      const auto _new_src = ptr(src->acknowledgmentFilter);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("acknowledgmentFilter", res);
    }

    if (src->severityFilter) {
      const auto _new_src = ptr(src->severityFilter);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "severityFilter");
        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = ptr(src->mostSevere);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("mostSevere", res);
        }

        {
          const auto _new_src = ptr(src->leastSevere);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("leastSevere", res);
        }

        res = container;
      }

      container->AssignField("severityFilter", res);
    }

    if (src->continueAfter) {
      const auto _new_src = ptr(src->continueAfter);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("continueAfter", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_GetAlarmEnrollmentSummary_Response(
    const GetAlarmEnrollmentSummary_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetAlarmEnrollmentSummary_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->listOfAlarmEnrollmentSummary);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type = get_field_type<VectorType>(
            container, "listOfAlarmEnrollmentSummary");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_AlarmEnrollmentSummary(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfAlarmEnrollmentSummary", res);
    }

    {
      const std::remove_pointer<decltype(src->moreFollows)>::type
          default_value = 0;
      const auto _new_src =
          ptr(src->moreFollows ? src->moreFollows : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("moreFollows", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_AlarmEnrollmentSummary(const AlarmEnrollmentSummary_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::AlarmEnrollmentSummary");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->eventEnrollmentName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventEnrollmentName", res);
    }

    {
      const auto _new_src = ptr(src->severity);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("severity", res);
    }

    {
      const auto _new_src = ptr(src->currentState);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("currentState", res);
    }

    {
      const std::remove_pointer<decltype(src->notificationLost)>::type
          default_value = 0;
      const auto _new_src =
          ptr(src->notificationLost ? src->notificationLost : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("notificationLost", res);
    }

    if (src->alarmAcknowledgmentRule) {
      const auto _new_src = ptr(src->alarmAcknowledgmentRule);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("alarmAcknowledgmentRule", res);
    }

    if (src->enrollementState) {
      const auto _new_src = ptr(src->enrollementState);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("enrollementState", res);
    }

    if (src->timeOfLastTransitionToActive) {
      const auto _new_src = ptr(src->timeOfLastTransitionToActive);
      const auto src = _new_src;
      const auto res = process_EventTime(src);
      container->AssignField("timeOfLastTransitionToActive", res);
    }

    if (src->timeActiveAcknowledged) {
      const auto _new_src = ptr(src->timeActiveAcknowledged);
      const auto src = _new_src;
      const auto res = process_EventTime(src);
      container->AssignField("timeActiveAcknowledged", res);
    }

    if (src->timeOfLastTransitionToIdle) {
      const auto _new_src = ptr(src->timeOfLastTransitionToIdle);
      const auto src = _new_src;
      const auto res = process_EventTime(src);
      container->AssignField("timeOfLastTransitionToIdle", res);
    }

    if (src->timeIdleAcknowledged) {
      const auto _new_src = ptr(src->timeIdleAcknowledged);
      const auto src = _new_src;
      const auto res = process_EventTime(src);
      container->AssignField("timeIdleAcknowledged", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_EventNotification(const EventNotification_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::EventNotification");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->eventEnrollmentName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventEnrollmentName", res);
    }

    {
      const auto _new_src = ptr(src->eventConditionName);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "eventConditionName");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present ==
            EventNotification__eventConditionName_PR_eventCondition) {
          const auto _new_src = ptr(src->choice.eventCondition);
          const auto src = _new_src;
          const auto res = process_ObjectName(src);
          container->AssignField("eventCondition", res);
        }

        if (src->present ==
            EventNotification__eventConditionName_PR_undefined) {
          const auto _new_src = ptr(src->choice.undefined);
          const auto src = _new_src;
          const auto res = true;
          container->AssignField("undefined", res);
        }

        res = container;
      }

      container->AssignField("eventConditionName", res);
    }

    {
      const auto _new_src = ptr(src->severity);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("severity", res);
    }

    if (src->currentState) {
      const auto _new_src = ptr(src->currentState);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("currentState", res);
    }

    {
      const auto _new_src = ptr(src->transitionTime);
      const auto src = _new_src;
      const auto res = process_EventTime(src);
      container->AssignField("transitionTime", res);
    }

    {
      const std::remove_pointer<decltype(src->notificationLost)>::type
          default_value = 0;
      const auto _new_src =
          ptr(src->notificationLost ? src->notificationLost : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("notificationLost", res);
    }

    if (src->alarmAcknowledgmentRule) {
      const auto _new_src = ptr(src->alarmAcknowledgmentRule);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("alarmAcknowledgmentRule", res);
    }

    if (src->actionResult) {
      const auto _new_src = ptr(src->actionResult);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "actionResult");
        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = ptr(src->eventActioName);
          const auto src = _new_src;
          const auto res = process_ObjectName(src);
          container->AssignField("eventActioName", res);
        }

        {
          const auto _new_src = ptr(src->eventActionResult);
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {
            static const auto type =
                get_field_type<RecordType>(container, "eventActionResult");
            const auto container = make_intrusive<RecordVal>(type);

            if (src->present ==
                EventNotification__actionResult__eventActionResult_PR_success) {
              const auto _new_src = ptr(src->choice.success);
              const auto src = _new_src;
              const auto res = process_ConfirmedServiceResponse(src);
              container->AssignField("success", res);
            }

            if (src->present ==
                EventNotification__actionResult__eventActionResult_PR_failure) {
              const auto _new_src = ptr(src->choice.failure);
              const auto src = _new_src;
              const auto res = process_ServiceError(src);
              container->AssignField("failure", res);
            }

            res = container;
          }

          container->AssignField("eventActionResult", res);
        }

        res = container;
      }

      container->AssignField("actionResult", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_AttachToEventCondition(const AttachToEventCondition_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::AttachToEventCondition");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->eventEnrollmentName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventEnrollmentName", res);
    }

    {
      const auto _new_src = ptr(src->eventConditionName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("eventConditionName", res);
    }

    {
      const auto _new_src = ptr(src->causingTransitions);
      const auto src = _new_src;
      const auto res = process_Transitions(src);
      container->AssignField("causingTransitions", res);
    }

    if (src->acceptableDelay) {
      const auto _new_src = ptr(src->acceptableDelay);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("acceptableDelay", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_EventTime(const EventTime_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::EventTime");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == EventTime_PR_timeOfDayT) {
      const auto _new_src = ptr(src->choice.timeOfDayT);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("timeOfDayT", res);
    }

    if (src->present == EventTime_PR_timeSequenceIdentifier) {
      const auto _new_src = ptr(src->choice.timeSequenceIdentifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("timeSequenceIdentifier", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Transitions(const Transitions_t *src) {
  static const auto type = id::find_type<VectorType>("mms::Transitions");
  static IntrusivePtr<EnumType> enum_type = nullptr;
  if (!enum_type) {
    auto subtype = type->Yield();
    if (!subtype || subtype->Tag() != TYPE_ENUM)
      reporter->InternalError("Unable to process 'Transitions': "
                              "%s is not a vector of enums",
                              type->GetName().c_str());
    enum_type = cast_intrusive<EnumType>(subtype);
  }
  auto res = make_intrusive<VectorVal>(type);
  if (src ? is_bit_set(src, 0) : false) /* idle-to-disabled */
    res->Append(enum_type->GetEnumVal(0));
  if (src ? is_bit_set(src, 1) : false) /* active-to-disabled */
    res->Append(enum_type->GetEnumVal(1));
  if (src ? is_bit_set(src, 2) : false) /* disabled-to-idle */
    res->Append(enum_type->GetEnumVal(2));
  if (src ? is_bit_set(src, 3) : false) /* active-to-idle */
    res->Append(enum_type->GetEnumVal(3));
  if (src ? is_bit_set(src, 4) : false) /* disabled-to-active */
    res->Append(enum_type->GetEnumVal(4));
  if (src ? is_bit_set(src, 5) : false) /* idle-to-active */
    res->Append(enum_type->GetEnumVal(5));
  if (src ? is_bit_set(src, 6) : false) /* any-to-deleted */
    res->Append(enum_type->GetEnumVal(6));
  return res;
}

IntrusivePtr<Val>
process_ReadJournal_Request(const ReadJournal_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ReadJournal_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->journalName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("journalName", res);
    }

    if (src->rangeStartSpecification) {
      const auto _new_src = ptr(src->rangeStartSpecification);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "rangeStartSpecification");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present ==
            ReadJournal_Request__rangeStartSpecification_PR_startingTime) {
          const auto _new_src = ptr(src->choice.startingTime);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("startingTime", res);
        }

        if (src->present ==
            ReadJournal_Request__rangeStartSpecification_PR_startingEntry) {
          const auto _new_src = ptr(src->choice.startingEntry);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("startingEntry", res);
        }

        res = container;
      }

      container->AssignField("rangeStartSpecification", res);
    }

    if (src->rangeStopSpecification) {
      const auto _new_src = ptr(src->rangeStopSpecification);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "rangeStopSpecification");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present ==
            ReadJournal_Request__rangeStopSpecification_PR_endingTime) {
          const auto _new_src = ptr(src->choice.endingTime);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("endingTime", res);
        }

        if (src->present ==
            ReadJournal_Request__rangeStopSpecification_PR_numberOfEntries) {
          const auto _new_src = ptr(src->choice.numberOfEntries);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("numberOfEntries", res);
        }

        res = container;
      }

      container->AssignField("rangeStopSpecification", res);
    }

    if (src->listOfVariables) {
      const auto _new_src = ptr(src->listOfVariables);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfVariables");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = convert(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfVariables", res);
    }

    {
      const auto _new_src = ptr(src->entryToStartAfter);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "entryToStartAfter");
        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = ptr(src->timeSpecification);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("timeSpecification", res);
        }

        {
          const auto _new_src = ptr(src->entrySpecification);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("entrySpecification", res);
        }

        res = container;
      }

      container->AssignField("entryToStartAfter", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_ReadJournal_Response(const ReadJournal_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ReadJournal_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->listOfJournalEntry);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfJournalEntry");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_JournalEntry(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfJournalEntry", res);
    }

    {
      const std::remove_pointer<decltype(src->moreFollows)>::type
          default_value = 0;
      const auto _new_src =
          ptr(src->moreFollows ? src->moreFollows : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("moreFollows", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_JournalEntry(const JournalEntry_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::JournalEntry");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->entryIdentifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("entryIdentifier", res);
    }

    {
      const auto _new_src = ptr(src->entryContent);
      const auto src = _new_src;
      const auto res = process_EntryContent(src);
      container->AssignField("entryContent", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_WriteJournal_Request(const WriteJournal_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::WriteJournal_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->journalName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("journalName", res);
    }

    {
      const auto _new_src = ptr(src->listOfJournalEntry);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfJournalEntry");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_EntryContent(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfJournalEntry", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_InitializeJournal_Request(const InitializeJournal_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::InitializeJournal_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->journalName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("journalName", res);
    }

    if (src->limitSpecification) {
      const auto _new_src = ptr(src->limitSpecification);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "limitSpecification");
        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = ptr(src->limitingTime);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("limitingTime", res);
        }

        if (src->limitingEntry) {
          const auto _new_src = ptr(src->limitingEntry);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("limitingEntry", res);
        }

        res = container;
      }

      container->AssignField("limitSpecification", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_InitializeJournal_Response(const InitializeJournal_Response_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val>
process_ReportJournalStatus_Request(const ReportJournalStatus_Request_t *src) {
  const auto res = process_ObjectName(src);
  return res;
}

IntrusivePtr<Val> process_ReportJournalStatus_Response(
    const ReportJournalStatus_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ReportJournalStatus_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->currentEntries);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("currentEntries", res);
    }

    {
      const auto _new_src = ptr(src->mmsDeletable);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mmsDeletable", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_CreateJournal_Request(const CreateJournal_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::CreateJournal_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->journalName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("journalName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_DeleteJournal_Request(const DeleteJournal_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DeleteJournal_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->journalName);
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("journalName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_EntryContent(const EntryContent_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::EntryContent");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->occurenceTime);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("occurenceTime", res);
    }

    if (src->additionalDetail) {
      const auto _new_src = ptr(src->additionalDetail);
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("additionalDetail", res);
    }

    {
      const auto _new_src = ptr(src->entryForm);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "entryForm");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present == EntryContent__entryForm_PR_data) {
          const auto _new_src = ptr(src->choice.data);
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {
            static const auto type =
                get_field_type<RecordType>(container, "data");
            const auto container = make_intrusive<RecordVal>(type);

            if (src->event) {
              const auto _new_src = ptr(src->event);
              const auto src = _new_src;

              IntrusivePtr<Val> res;
              {
                static const auto type =
                    get_field_type<RecordType>(container, "_event");
                const auto container = make_intrusive<RecordVal>(type);

                {
                  const auto _new_src = ptr(src->eventConditionName);
                  const auto src = _new_src;
                  const auto res = process_ObjectName(src);
                  container->AssignField("eventConditionName", res);
                }

                {
                  const auto _new_src = ptr(src->currentState);
                  const auto src = _new_src;
                  const auto res = convert(src);
                  container->AssignField("currentState", res);
                }

                res = container;
              }

              container->AssignField("_event", res);
            }

            if (src->listOfVariables) {
              const auto _new_src = ptr(src->listOfVariables);
              const auto src = _new_src;

              IntrusivePtr<Val> res;
              {
                static const auto type =
                    get_field_type<VectorType>(container, "listOfVariables");
                const auto container = make_intrusive<VectorVal>(type);
                for (int i = 0; i < src->list.count; i++) {
                  const auto _new_src = src->list.array[i];
                  const auto src = _new_src;

                  IntrusivePtr<Val> res;
                  {
                    static const auto type =
                        get_field_type<RecordType>(container);
                    const auto container = make_intrusive<RecordVal>(type);

                    {
                      const auto _new_src = ptr(src->variableTag);
                      const auto src = _new_src;
                      const auto res = convert(src);
                      container->AssignField("variableTag", res);
                    }

                    {
                      const auto _new_src = ptr(src->valueSpecification);
                      const auto src = _new_src;
                      const auto res = process_Data(src);
                      container->AssignField("valueSpecification", res);
                    }

                    res = container;
                  }

                  container->Append(res);
                }
                res = container;
              }

              container->AssignField("listOfVariables", res);
            }

            res = container;
          }

          container->AssignField("data", res);
        }

        if (src->present == EntryContent__entryForm_PR_annotation) {
          const auto _new_src = ptr(src->choice.annotation);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("annotation", res);
        }

        res = container;
      }

      container->AssignField("entryForm", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ObtainFile_Request(const ObtainFile_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ObtainFile_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->sourceFile);
      const auto src = _new_src;
      const auto res = process_FileName(src);
      container->AssignField("sourceFile", res);
    }

    {
      const auto _new_src = ptr(src->destinationFile);
      const auto src = _new_src;
      const auto res = process_FileName(src);
      container->AssignField("destinationFile", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_FileOpen_Request(const FileOpen_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::FileOpen_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->fileName);
      const auto src = _new_src;
      const auto res = process_FileName(src);
      container->AssignField("fileName", res);
    }

    {
      const auto _new_src = ptr(src->initialPosition);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("initialPosition", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_FileOpen_Response(const FileOpen_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::FileOpen_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->frsmID);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("frsmID", res);
    }

    {
      const auto _new_src = ptr(src->fileAttributes);
      const auto src = _new_src;
      const auto res = process_FileAttributes(src);
      container->AssignField("fileAttributes", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_FileRead_Request(const FileRead_Request_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_FileRead_Response(const FileRead_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::FileRead_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->fileData);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("fileData", res);
    }

    {
      const std::remove_pointer<decltype(src->moreFollows)>::type
          default_value = 1;
      const auto _new_src =
          ptr(src->moreFollows ? src->moreFollows : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("moreFollows", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_FileClose_Request(const FileClose_Request_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_FileRename_Request(const FileRename_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::FileRename_Request");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->currentFileName);
      const auto src = _new_src;
      const auto res = process_FileName(src);
      container->AssignField("currentFileName", res);
    }

    {
      const auto _new_src = ptr(src->newFileName);
      const auto src = _new_src;
      const auto res = process_FileName(src);
      container->AssignField("newFileName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_FileDelete_Request(const FileDelete_Request_t *src) {
  const auto res = process_FileName(src);
  return res;
}

IntrusivePtr<Val>
process_FileDirectory_Request(const FileDirectory_Request_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::FileDirectory_Request");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->fileSpecification) {
      const auto _new_src = ptr(src->fileSpecification);
      const auto src = _new_src;
      const auto res = process_FileName(src);
      container->AssignField("fileSpecification", res);
    }

    if (src->continueAfter) {
      const auto _new_src = ptr(src->continueAfter);
      const auto src = _new_src;
      const auto res = process_FileName(src);
      container->AssignField("continueAfter", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_FileDirectory_Response(const FileDirectory_Response_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::FileDirectory_Response");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->listOfDirectoryEntry);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "listOfDirectoryEntry");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_DirectoryEntry(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfDirectoryEntry", res);
    }

    {
      const std::remove_pointer<decltype(src->moreFollows)>::type
          default_value = 0;
      const auto _new_src =
          ptr(src->moreFollows ? src->moreFollows : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("moreFollows", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_DirectoryEntry(const DirectoryEntry_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::DirectoryEntry");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->filename);
      const auto src = _new_src;
      const auto res = process_FileName(src);
      container->AssignField("filename", res);
    }

    {
      const auto _new_src = ptr(src->fileAttributes);
      const auto src = _new_src;
      const auto res = process_FileAttributes(src);
      container->AssignField("fileAttributes", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_FileAttributes(const FileAttributes_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::FileAttributes");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->sizeOfFile);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("sizeOfFile", res);
    }

    if (src->lastModified) {
      const auto _new_src = ptr(src->lastModified);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("lastModified", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_EXTERNALt(const EXTERNALt_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::EXTERNALt");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->direct_reference) {
      const auto _new_src = ptr(src->direct_reference);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("direct_reference", res);
    }

    if (src->indirect_reference) {
      const auto _new_src = ptr(src->indirect_reference);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("indirect_reference", res);
    }

    if (src->data_value_descriptor) {
      const auto _new_src = ptr(src->data_value_descriptor);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("data_value_descriptor", res);
    }

    {
      const auto _new_src = ptr(src->encoding);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "encoding");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present == EXTERNALt__encoding_PR_single_ASN1_type) {
          const auto _new_src = ptr(src->choice.single_ASN1_type);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("single_ASN1_type", res);
        }

        if (src->present == EXTERNALt__encoding_PR_octet_aligned) {
          const auto _new_src = ptr(src->choice.octet_aligned);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("octet_aligned", res);
        }

        if (src->present == EXTERNALt__encoding_PR_arbitrary) {
          const auto _new_src = ptr(src->choice.arbitrary);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("arbitrary", res);
        }

        res = container;
      }

      container->AssignField("encoding", res);
    }

    res = container;
  }
  return res;
}

} // namespace zeek::plugin::mms
