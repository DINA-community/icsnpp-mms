/* THIS CODE IS GENERATED. DON'T CHANGE MANUALLY! */

#include "process.h"
#include "zeek/Val.h"

#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"

using namespace zeek;

namespace {

IntrusivePtr<Val> convert(const int *i) { return make_intrusive<IntVal>(*i); }
IntrusivePtr<Val> convert(const long int *i) {
  return make_intrusive<IntVal>(*i);
}
IntrusivePtr<Val> convert(const unsigned int *i) {
  return make_intrusive<IntVal>(*i);
}
IntrusivePtr<Val> convert(const long unsigned int *i) {
  return make_intrusive<IntVal>(*i);
}
IntrusivePtr<Val> convert(int i) { return make_intrusive<IntVal>(i); }
IntrusivePtr<Val> convert(long int i) { return make_intrusive<IntVal>(i); }
IntrusivePtr<Val> convert(unsigned int i) { return make_intrusive<IntVal>(i); }
IntrusivePtr<Val> convert(long unsigned int i) {
  return make_intrusive<IntVal>(i);
}

template <typename T> IntrusivePtr<Val> convert(const T *s) {
  return make_intrusive<StringVal>(s->size,
                                   reinterpret_cast<const char *>(s->buf));
}

bool is_bit_set(BIT_STRING_t *s, unsigned int idx) {
  int byte_no = idx / 8;
  if (byte_no >= s->size)
    return false;
  auto byte = s->buf[byte_no];
  return byte & (1 << (idx % 8));
}

#ifdef _OBJECT_IDENTIFIER_H_
IntrusivePtr<Val> convert(OBJECT_IDENTIFIER_t *oid) {
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
} // namespace

namespace zeek::plugin::mms {

IntrusivePtr<Val> process_MmsPdu(MmsPdu_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::MmsPdu");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == MmsPdu_PR_confirmedRequestPdu) {
      const auto _new_src = &src->choice.confirmedRequestPdu;
      const auto src = _new_src;
      const auto res = process_ConfirmedRequestPdu(src);
      container->AssignField("confirmedRequestPdu", res);
    }

    if (src->present == MmsPdu_PR_confirmedResponsePdu) {
      const auto _new_src = &src->choice.confirmedResponsePdu;
      const auto src = _new_src;
      const auto res = process_ConfirmedResponsePdu(src);
      container->AssignField("confirmedResponsePdu", res);
    }

    if (src->present == MmsPdu_PR_unconfirmedPDU) {
      const auto _new_src = &src->choice.unconfirmedPDU;
      const auto src = _new_src;
      const auto res = process_UnconfirmedPDU(src);
      container->AssignField("unconfirmedPDU", res);
    }

    if (src->present == MmsPdu_PR_initiateRequestPdu) {
      const auto _new_src = &src->choice.initiateRequestPdu;
      const auto src = _new_src;
      const auto res = process_InitiateRequestPdu(src);
      container->AssignField("initiateRequestPdu", res);
    }

    if (src->present == MmsPdu_PR_initiateResponsePdu) {
      const auto _new_src = &src->choice.initiateResponsePdu;
      const auto src = _new_src;
      const auto res = process_InitiateResponsePdu(src);
      container->AssignField("initiateResponsePdu", res);
    }

    if (src->present == MmsPdu_PR_initiateErrorPdu) {
      const auto _new_src = &src->choice.initiateErrorPdu;
      const auto src = _new_src;
      const auto res = process_ServiceError(src);
      container->AssignField("initiateErrorPdu", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_UnconfirmedPDU(UnconfirmedPDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::UnconfirmedPDU");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = &src->unconfirmedService;
      const auto src = _new_src;
      const auto res = process_UnconfirmedService(src);
      container->AssignField("unconfirmedService", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_UnconfirmedService(UnconfirmedService_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::UnconfirmedService");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == UnconfirmedService_PR_informationReport) {
      const auto _new_src = &src->choice.informationReport;
      const auto src = _new_src;
      const auto res = process_InformationReport(src);
      container->AssignField("informationReport", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ConfirmedRequestPdu(ConfirmedRequestPdu_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ConfirmedRequestPdu");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = &src->invokeID;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("invokeID", res);
    }

    {
      const auto _new_src = &src->confirmedServiceRequest;
      const auto src = _new_src;
      const auto res = process_ConfirmedServiceRequest(src);
      container->AssignField("confirmedServiceRequest", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ConfirmedResponsePdu(ConfirmedResponsePdu_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ConfirmedResponsePdu");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = &src->invokeID;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("invokeID", res);
    }

    {
      const auto _new_src = &src->confirmedServiceResponse;
      const auto src = _new_src;
      const auto res = process_ConfirmedServiceResponse(src);
      container->AssignField("confirmedServiceResponse", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_ConfirmedServiceRequest(ConfirmedServiceRequest_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ConfirmedServiceRequest");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == ConfirmedServiceRequest_PR_getNameList) {
      const auto _new_src = &src->choice.getNameList;
      const auto src = _new_src;
      const auto res = process_GetNameListRequest(src);
      container->AssignField("getNameList", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_read) {
      const auto _new_src = &src->choice.read;
      const auto src = _new_src;
      const auto res = process_ReadRequest(src);
      container->AssignField("read", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_write) {
      const auto _new_src = &src->choice.write;
      const auto src = _new_src;
      const auto res = process_WriteRequest(src);
      container->AssignField("write", res);
    }

    if (src->present ==
        ConfirmedServiceRequest_PR_getVariableAccessAttributes) {
      const auto _new_src = &src->choice.getVariableAccessAttributes;
      const auto src = _new_src;
      const auto res = process_GetVariableAccessAttributesRequest(src);
      container->AssignField("getVariableAccessAttributes", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_defineNamedVariableList) {
      const auto _new_src = &src->choice.defineNamedVariableList;
      const auto src = _new_src;
      const auto res = process_DefineNamedVariableListRequest(src);
      container->AssignField("defineNamedVariableList", res);
    }

    if (src->present ==
        ConfirmedServiceRequest_PR_getNamedVariableListAttributes) {
      const auto _new_src = &src->choice.getNamedVariableListAttributes;
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("getNamedVariableListAttributes", res);
    }

    if (src->present == ConfirmedServiceRequest_PR_deleteNamedVariableList) {
      const auto _new_src = &src->choice.deleteNamedVariableList;
      const auto src = _new_src;
      const auto res = process_DeleteNamedVariableListRequest(src);
      container->AssignField("deleteNamedVariableList", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_ConfirmedServiceResponse(ConfirmedServiceResponse_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::ConfirmedServiceResponse");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == ConfirmedServiceResponse_PR_getNameList) {
      const auto _new_src = &src->choice.getNameList;
      const auto src = _new_src;
      const auto res = process_GetNameListResponse(src);
      container->AssignField("getNameList", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_read) {
      const auto _new_src = &src->choice.read;
      const auto src = _new_src;
      const auto res = process_ReadResponse(src);
      container->AssignField("read", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_write) {
      const auto _new_src = &src->choice.write;
      const auto src = _new_src;
      const auto res = process_WriteResponse(src);
      container->AssignField("write", res);
    }

    if (src->present ==
        ConfirmedServiceResponse_PR_getVariableAccessAttributes) {
      const auto _new_src = &src->choice.getVariableAccessAttributes;
      const auto src = _new_src;
      const auto res = process_GetVariableAccessAttributesResponse(src);
      container->AssignField("getVariableAccessAttributes", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_defineNamedVariableList) {
      const auto _new_src = &src->choice.defineNamedVariableList;
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("defineNamedVariableList", res);
    }

    if (src->present ==
        ConfirmedServiceResponse_PR_getNamedVariableListAttributes) {
      const auto _new_src = &src->choice.getNamedVariableListAttributes;
      const auto src = _new_src;
      const auto res = process_GetNamedVariableListAttributesResponse(src);
      container->AssignField("getNamedVariableListAttributes", res);
    }

    if (src->present == ConfirmedServiceResponse_PR_deleteNamedVariableList) {
      const auto _new_src = &src->choice.deleteNamedVariableList;
      const auto src = _new_src;
      const auto res = process_DeleteNamedVariableListResponse(src);
      container->AssignField("deleteNamedVariableList", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ObjectName(ObjectName_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::ObjectName");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == ObjectName_PR_vmdSpecific) {
      const auto _new_src = &src->choice.vmdSpecific;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("vmdSpecific", res);
    }

    if (src->present == ObjectName_PR_domainSpecific) {
      const auto _new_src = &src->choice.domainSpecific;
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<RecordType> type = nullptr;
        if (!type) {
          auto container_type =
              cast_intrusive<RecordType>(container->GetType());
          if (!container_type->HasField("domainSpecific"))
            reporter->InternalError(
                "Unable to process 'ObjectName__domainSpecific': "
                "Missing field 'domainSpecific' in %s",
                container_type->GetName().c_str());
          auto field_type = container_type->GetFieldType("domainSpecific");
          if (field_type->Tag() != TYPE_RECORD)
            reporter->InternalError(
                "Unable to process 'ObjectName__domainSpecific': "
                "Field 'domainSpecific' in %s is not of type RecordType",
                container_type->GetName().c_str());
          type = cast_intrusive<RecordType>(field_type);
        }

        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = &src->domainId;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("domainId", res);
        }

        {
          const auto _new_src = &src->itemId;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("itemId", res);
        }

        res = container;
      }

      container->AssignField("domainSpecific", res);
    }

    if (src->present == ObjectName_PR_aaSpecific) {
      const auto _new_src = &src->choice.aaSpecific;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("aaSpecific", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_InitiateErrorPdu(InitiateErrorPdu_t *src) {
  const auto res = process_ServiceError(src);
  return res;
}

IntrusivePtr<Val> process_InitiateRequestPdu(InitiateRequestPdu_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::InitiateRequestPdu");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->localDetailCalling) {
      const auto _new_src = src->localDetailCalling;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("localDetailCalling", res);
    }

    {
      const auto _new_src = &src->proposedMaxServOutstandingCalling;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("proposedMaxServOutstandingCalling", res);
    }

    {
      const auto _new_src = &src->proposedMaxServOutstandingCalled;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("proposedMaxServOutstandingCalled", res);
    }

    if (src->proposedDataStructureNestingLevel) {
      const auto _new_src = src->proposedDataStructureNestingLevel;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("proposedDataStructureNestingLevel", res);
    }

    {
      const auto _new_src = &src->mmsInitRequestDetail;
      const auto src = _new_src;
      const auto res = process_InitRequestDetail(src);
      container->AssignField("mmsInitRequestDetail", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_InitRequestDetail(InitRequestDetail_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::InitRequestDetail");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = &src->proposedVersionNumber;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("proposedVersionNumber", res);
    }

    {
      const auto _new_src = &src->proposedParameterCBB;
      const auto src = _new_src;
      const auto res = process_ParameterSupportOptions(src);
      container->AssignField("proposedParameterCBB", res);
    }

    {
      const auto _new_src = &src->servicesSupportedCalling;
      const auto src = _new_src;
      const auto res = process_ServiceSupportOptions(src);
      container->AssignField("servicesSupportedCalling", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_InitiateResponsePdu(InitiateResponsePdu_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::InitiateResponsePdu");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->localDetailCalled) {
      const auto _new_src = src->localDetailCalled;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("localDetailCalled", res);
    }

    {
      const auto _new_src = &src->negotiatedMaxServOutstandingCalling;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("negotiatedMaxServOutstandingCalling", res);
    }

    {
      const auto _new_src = &src->negotiatedMaxServOutstandingCalled;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("negotiatedMaxServOutstandingCalled", res);
    }

    if (src->negotiatedDataStructureNestingLevel) {
      const auto _new_src = src->negotiatedDataStructureNestingLevel;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("negotiatedDataStructureNestingLevel", res);
    }

    {
      const auto _new_src = &src->mmsInitResponseDetail;
      const auto src = _new_src;
      const auto res = process_InitResponseDetail(src);
      container->AssignField("mmsInitResponseDetail", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_InitResponseDetail(InitResponseDetail_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::InitResponseDetail");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = &src->negotiatedVersionNumber;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("negotiatedVersionNumber", res);
    }

    {
      const auto _new_src = &src->negotiatedParameterCBB;
      const auto src = _new_src;
      const auto res = process_ParameterSupportOptions(src);
      container->AssignField("negotiatedParameterCBB", res);
    }

    {
      const auto _new_src = &src->servicesSupportedCalled;
      const auto src = _new_src;
      const auto res = process_ServiceSupportOptions(src);
      container->AssignField("servicesSupportedCalled", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_ParameterSupportOptions(ParameterSupportOptions_t *src) {
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

IntrusivePtr<Val> process_ServiceSupportOptions(ServiceSupportOptions_t *src) {
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
  if (src ? is_bit_set(src, 56) : false) /* reportEventActionStatus */
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

IntrusivePtr<Val> process_ServiceError(ServiceError_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::ServiceError");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = &src->errorClass;
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<RecordType> type = nullptr;
        if (!type) {
          auto container_type =
              cast_intrusive<RecordType>(container->GetType());
          if (!container_type->HasField("errorClass"))
            reporter->InternalError(
                "Unable to process 'ServiceError__errorClass': "
                "Missing field 'errorClass' in %s",
                container_type->GetName().c_str());
          auto field_type = container_type->GetFieldType("errorClass");
          if (field_type->Tag() != TYPE_RECORD)
            reporter->InternalError(
                "Unable to process 'ServiceError__errorClass': "
                "Field 'errorClass' in %s is not of type RecordType",
                container_type->GetName().c_str());
          type = cast_intrusive<RecordType>(field_type);
        }

        const auto container = make_intrusive<RecordVal>(type);

        if (src->present == ServiceError__errorClass_PR_vmdState) {
          const auto _new_src = &src->choice.vmdState;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("vmdState", res);
        }

        if (src->present == ServiceError__errorClass_PR_applicationReference) {
          const auto _new_src = &src->choice.applicationReference;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("applicationReference", res);
        }

        if (src->present == ServiceError__errorClass_PR_definition) {
          const auto _new_src = &src->choice.definition;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("definition", res);
        }

        if (src->present == ServiceError__errorClass_PR_resource) {
          const auto _new_src = &src->choice.resource;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("resource", res);
        }

        if (src->present == ServiceError__errorClass_PR_service) {
          const auto _new_src = &src->choice.service;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("service", res);
        }

        if (src->present == ServiceError__errorClass_PR_servicePreempt) {
          const auto _new_src = &src->choice.servicePreempt;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("servicePreempt", res);
        }

        if (src->present == ServiceError__errorClass_PR_timeResolution) {
          const auto _new_src = &src->choice.timeResolution;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("timeResolution", res);
        }

        if (src->present == ServiceError__errorClass_PR_access) {
          const auto _new_src = &src->choice.access;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("access", res);
        }

        if (src->present == ServiceError__errorClass_PR_initiate) {
          const auto _new_src = &src->choice.initiate;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("initiate", res);
        }

        if (src->present == ServiceError__errorClass_PR_conclude) {
          const auto _new_src = &src->choice.conclude;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("conclude", res);
        }

        if (src->present == ServiceError__errorClass_PR_cancel) {
          const auto _new_src = &src->choice.cancel;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("_cancel", res);
        }

        if (src->present == ServiceError__errorClass_PR_file) {
          const auto _new_src = &src->choice.file;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("_file", res);
        }

        if (src->present == ServiceError__errorClass_PR_others) {
          const auto _new_src = &src->choice.others;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("others", res);
        }

        res = container;
      }

      container->AssignField("errorClass", res);
    }

    if (src->additionalCode) {
      const auto _new_src = src->additionalCode;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("additionalCode", res);
    }

    if (src->additionalDescription) {
      const auto _new_src = src->additionalDescription;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("additionalDescription", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_GetNameListRequest(GetNameListRequest_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetNameListRequest");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = &src->objectClass;
      const auto src = _new_src;
      const auto res = process_ObjectClass(src);
      container->AssignField("objectClass", res);
    }

    {
      const auto _new_src = &src->objectScope;
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<RecordType> type = nullptr;
        if (!type) {
          auto container_type =
              cast_intrusive<RecordType>(container->GetType());
          if (!container_type->HasField("objectScope"))
            reporter->InternalError(
                "Unable to process 'GetNameListRequest__objectScope': "
                "Missing field 'objectScope' in %s",
                container_type->GetName().c_str());
          auto field_type = container_type->GetFieldType("objectScope");
          if (field_type->Tag() != TYPE_RECORD)
            reporter->InternalError(
                "Unable to process 'GetNameListRequest__objectScope': "
                "Field 'objectScope' in %s is not of type RecordType",
                container_type->GetName().c_str());
          type = cast_intrusive<RecordType>(field_type);
        }

        const auto container = make_intrusive<RecordVal>(type);

        if (src->present == GetNameListRequest__objectScope_PR_vmdSpecific) {
          const auto _new_src = &src->choice.vmdSpecific;
          const auto src = _new_src;
          const auto res = true;
          container->AssignField("vmdSpecific", res);
        }

        if (src->present == GetNameListRequest__objectScope_PR_domainSpecific) {
          const auto _new_src = &src->choice.domainSpecific;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("domainSpecific", res);
        }

        if (src->present == GetNameListRequest__objectScope_PR_aaSpecific) {
          const auto _new_src = &src->choice.aaSpecific;
          const auto src = _new_src;
          const auto res = true;
          container->AssignField("aaSpecific", res);
        }

        res = container;
      }

      container->AssignField("objectScope", res);
    }

    if (src->continueAfter) {
      const auto _new_src = src->continueAfter;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("continueAfter", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ObjectClass(ObjectClass_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::ObjectClass");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == ObjectClass_PR_basicObjectClass) {
      const auto _new_src = &src->choice.basicObjectClass;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("basicObjectClass", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_GetNameListResponse(GetNameListResponse_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetNameListResponse");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = &src->listOfIdentifier;
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<VectorType> type = nullptr;
        if (!type) {
          auto container_type =
              cast_intrusive<RecordType>(container->GetType());
          if (!container_type->HasField("listOfIdentifier"))
            reporter->InternalError(
                "Unable to process 'GetNameListResponse__listOfIdentifier': "
                "Missing field 'listOfIdentifier' in %s",
                container_type->GetName().c_str());
          auto field_type = container_type->GetFieldType("listOfIdentifier");
          if (field_type->Tag() != TYPE_VECTOR)
            reporter->InternalError(
                "Unable to process 'GetNameListResponse__listOfIdentifier': "
                "Field 'listOfIdentifier' in %s is not of type VectorType",
                container_type->GetName().c_str());
          type = cast_intrusive<VectorType>(field_type);
        }

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
      const auto _new_src = src->moreFollows ? *src->moreFollows : true;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("moreFollows", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_TypeSpecification(TypeSpecification_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::TypeSpecification");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == TypeSpecification_PR_array) {
      const auto _new_src = &src->choice.array;
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<RecordType> type = nullptr;
        if (!type) {
          auto container_type =
              cast_intrusive<RecordType>(container->GetType());
          if (!container_type->HasField("array"))
            reporter->InternalError(
                "Unable to process 'TypeSpecification__array': "
                "Missing field 'array' in %s",
                container_type->GetName().c_str());
          auto field_type = container_type->GetFieldType("array");
          if (field_type->Tag() != TYPE_RECORD)
            reporter->InternalError(
                "Unable to process 'TypeSpecification__array': "
                "Field 'array' in %s is not of type RecordType",
                container_type->GetName().c_str());
          type = cast_intrusive<RecordType>(field_type);
        }

        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = src->packed ? *src->packed : false;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("packed", res);
        }

        {
          const auto _new_src = &src->numberOfElements;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("numberOfElements", res);
        }

        {
          const auto _new_src = src->elementType;
          const auto src = _new_src;
          const auto res = process_TypeSpecification(src);
          container->AssignField("elementType", res);
        }

        res = container;
      }

      container->AssignField("array", res);
    }

    if (src->present == TypeSpecification_PR_structure) {
      const auto _new_src = &src->choice.structure;
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<RecordType> type = nullptr;
        if (!type) {
          auto container_type =
              cast_intrusive<RecordType>(container->GetType());
          if (!container_type->HasField("structure"))
            reporter->InternalError(
                "Unable to process 'TypeSpecification__structure': "
                "Missing field 'structure' in %s",
                container_type->GetName().c_str());
          auto field_type = container_type->GetFieldType("structure");
          if (field_type->Tag() != TYPE_RECORD)
            reporter->InternalError(
                "Unable to process 'TypeSpecification__structure': "
                "Field 'structure' in %s is not of type RecordType",
                container_type->GetName().c_str());
          type = cast_intrusive<RecordType>(field_type);
        }

        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = src->packed ? *src->packed : false;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("packed", res);
        }

        {
          const auto _new_src = &src->components;
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {

            static IntrusivePtr<VectorType> type = nullptr;
            if (!type) {
              auto container_type =
                  cast_intrusive<RecordType>(container->GetType());
              if (!container_type->HasField("components"))
                reporter->InternalError(
                    "Unable to process 'structure__components': "
                    "Missing field 'components' in %s",
                    container_type->GetName().c_str());
              auto field_type = container_type->GetFieldType("components");
              if (field_type->Tag() != TYPE_VECTOR)
                reporter->InternalError(
                    "Unable to process 'structure__components': "
                    "Field 'components' in %s is not of type VectorType",
                    container_type->GetName().c_str());
              type = cast_intrusive<VectorType>(field_type);
            }

            const auto container = make_intrusive<VectorVal>(type);
            for (int i = 0; i < src->list.count; i++) {
              const auto _new_src = src->list.array[i];
              const auto src = _new_src;
              const auto res = process_StructComponent(src);
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
      const auto _new_src = &src->choice.boolean;
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("boolean", res);
    }

    if (src->present == TypeSpecification_PR_bitString) {
      const auto _new_src = &src->choice.bitString;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("bitString", res);
    }

    if (src->present == TypeSpecification_PR_integer) {
      const auto _new_src = &src->choice.integer;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("integer", res);
    }

    if (src->present == TypeSpecification_PR_unsigned) {
      const auto _new_src = &src->choice.Unsigned;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("unsigned", res);
    }

    if (src->present == TypeSpecification_PR_floatingPoint) {
      const auto _new_src = &src->choice.floatingPoint;
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<RecordType> type = nullptr;
        if (!type) {
          auto container_type =
              cast_intrusive<RecordType>(container->GetType());
          if (!container_type->HasField("floatingPoint"))
            reporter->InternalError(
                "Unable to process 'TypeSpecification__floatingPoint': "
                "Missing field 'floatingPoint' in %s",
                container_type->GetName().c_str());
          auto field_type = container_type->GetFieldType("floatingPoint");
          if (field_type->Tag() != TYPE_RECORD)
            reporter->InternalError(
                "Unable to process 'TypeSpecification__floatingPoint': "
                "Field 'floatingPoint' in %s is not of type RecordType",
                container_type->GetName().c_str());
          type = cast_intrusive<RecordType>(field_type);
        }

        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = &src->formatWidth;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("formatWidth", res);
        }

        {
          const auto _new_src = &src->exponentWidth;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("exponentWidth", res);
        }

        res = container;
      }

      container->AssignField("floatingPoint", res);
    }

    if (src->present == TypeSpecification_PR_octetString) {
      const auto _new_src = &src->choice.octetString;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("octetString", res);
    }

    if (src->present == TypeSpecification_PR_visibleString) {
      const auto _new_src = &src->choice.visibleString;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("visibleString", res);
    }

    if (src->present == TypeSpecification_PR_binaryTime) {
      const auto _new_src = &src->choice.binaryTime;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("binaryTime", res);
    }

    if (src->present == TypeSpecification_PR_mmsString) {
      const auto _new_src = &src->choice.mmsString;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mmsString", res);
    }

    if (src->present == TypeSpecification_PR_utcTime) {
      const auto _new_src = &src->choice.utcTime;
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("utcTime", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_StructComponent(StructComponent_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::StructComponent");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->componentName) {
      const auto _new_src = src->componentName;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("componentName", res);
    }

    {
      const auto _new_src = src->componentType;
      const auto src = _new_src;
      const auto res = process_TypeSpecification(src);
      container->AssignField("componentType", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_AlternateAccess(AlternateAccess_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<VectorType>("mms::AlternateAccess");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<RecordType> type = nullptr;
        if (!type) {
          auto subtype = container->GetType()->Yield();
          if (!subtype || subtype->Tag() != TYPE_RECORD)
            reporter->InternalError(
                "Unable to process 'AlternateAccess__Member': "
                "Content of %s is not of type RecordType",
                container->GetType()->GetName().c_str());
          type = cast_intrusive<RecordType>(subtype);
        }

        const auto container = make_intrusive<RecordVal>(type);

        if (src->present == AlternateAccess__Member_PR_selectAlternateAccess) {
          const auto _new_src = &src->choice.selectAlternateAccess;
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {

            static IntrusivePtr<RecordType> type = nullptr;
            if (!type) {
              auto container_type =
                  cast_intrusive<RecordType>(container->GetType());
              if (!container_type->HasField("selectAlternateAccess"))
                reporter->InternalError(
                    "Unable to process 'Member__selectAlternateAccess': "
                    "Missing field 'selectAlternateAccess' in %s",
                    container_type->GetName().c_str());
              auto field_type =
                  container_type->GetFieldType("selectAlternateAccess");
              if (field_type->Tag() != TYPE_RECORD)
                reporter->InternalError(
                    "Unable to process 'Member__selectAlternateAccess': "
                    "Field 'selectAlternateAccess' in %s is not of type "
                    "RecordType",
                    container_type->GetName().c_str());
              type = cast_intrusive<RecordType>(field_type);
            }

            const auto container = make_intrusive<RecordVal>(type);

            {
              const auto _new_src = &src->accessSelection;
              const auto src = _new_src;

              IntrusivePtr<Val> res;
              {

                static IntrusivePtr<RecordType> type = nullptr;
                if (!type) {
                  auto container_type =
                      cast_intrusive<RecordType>(container->GetType());
                  if (!container_type->HasField("accessSelection"))
                    reporter->InternalError(
                        "Unable to process "
                        "'selectAlternateAccess__accessSelection': "
                        "Missing field 'accessSelection' in %s",
                        container_type->GetName().c_str());
                  auto field_type =
                      container_type->GetFieldType("accessSelection");
                  if (field_type->Tag() != TYPE_RECORD)
                    reporter->InternalError(
                        "Unable to process "
                        "'selectAlternateAccess__accessSelection': "
                        "Field 'accessSelection' in %s is not of type "
                        "RecordType",
                        container_type->GetName().c_str());
                  type = cast_intrusive<RecordType>(field_type);
                }

                const auto container = make_intrusive<RecordVal>(type);

                if (src->present ==
                    selectAlternateAccess__accessSelection_PR_component) {
                  const auto _new_src = &src->choice.component;
                  const auto src = _new_src;
                  const auto res = convert(src);
                  container->AssignField("component", res);
                }

                if (src->present ==
                    selectAlternateAccess__accessSelection_PR_index) {
                  const auto _new_src = &src->choice.index;
                  const auto src = _new_src;
                  const auto res = convert(src);
                  container->AssignField("index", res);
                }

                if (src->present ==
                    selectAlternateAccess__accessSelection_PR_indexRange) {
                  const auto _new_src = &src->choice.indexRange;
                  const auto src = _new_src;

                  IntrusivePtr<Val> res;
                  {

                    static IntrusivePtr<RecordType> type = nullptr;
                    if (!type) {
                      auto container_type =
                          cast_intrusive<RecordType>(container->GetType());
                      if (!container_type->HasField("indexRange"))
                        reporter->InternalError(
                            "Unable to process 'accessSelection__indexRange': "
                            "Missing field 'indexRange' in %s",
                            container_type->GetName().c_str());
                      auto field_type =
                          container_type->GetFieldType("indexRange");
                      if (field_type->Tag() != TYPE_RECORD)
                        reporter->InternalError(
                            "Unable to process 'accessSelection__indexRange': "
                            "Field 'indexRange' in %s is not of type "
                            "RecordType",
                            container_type->GetName().c_str());
                      type = cast_intrusive<RecordType>(field_type);
                    }

                    const auto container = make_intrusive<RecordVal>(type);

                    {
                      const auto _new_src = &src->lowIndex;
                      const auto src = _new_src;
                      const auto res = convert(src);
                      container->AssignField("lowIndex", res);
                    }

                    {
                      const auto _new_src = &src->numberOfElements;
                      const auto src = _new_src;
                      const auto res = convert(src);
                      container->AssignField("numberOfElements", res);
                    }

                    res = container;
                  }

                  container->AssignField("indexRange", res);
                }

                if (src->present ==
                    selectAlternateAccess__accessSelection_PR_allElements) {
                  const auto _new_src = &src->choice.allElements;
                  const auto src = _new_src;
                  const auto res = true;
                  container->AssignField("allElements", res);
                }

                res = container;
              }

              container->AssignField("accessSelection", res);
            }

            {
              const auto _new_src = src->alternateAccess;
              const auto src = _new_src;
              const auto res = process_AlternateAccess(src);
              container->AssignField("alternateAccess", res);
            }

            res = container;
          }

          container->AssignField("selectAlternateAccess", res);
        }

        if (src->present == AlternateAccess__Member_PR_component) {
          const auto _new_src = &src->choice.component;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("component", res);
        }

        if (src->present == AlternateAccess__Member_PR_index) {
          const auto _new_src = &src->choice.index;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("index", res);
        }

        if (src->present == AlternateAccess__Member_PR_indexRange) {
          const auto _new_src = &src->choice.indexRange;
          const auto src = _new_src;
          const auto res = process_IndexRangeSeq(src);
          container->AssignField("indexRange", res);
        }

        if (src->present == AlternateAccess__Member_PR_allElements) {
          const auto _new_src = &src->choice.allElements;
          const auto src = _new_src;
          const auto res = true;
          container->AssignField("allElements", res);
        }

        if (src->present == AlternateAccess__Member_PR_named) {
          const auto _new_src = &src->choice.named;
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {

            static IntrusivePtr<RecordType> type = nullptr;
            if (!type) {
              auto container_type =
                  cast_intrusive<RecordType>(container->GetType());
              if (!container_type->HasField("named"))
                reporter->InternalError("Unable to process 'Member__named': "
                                        "Missing field 'named' in %s",
                                        container_type->GetName().c_str());
              auto field_type = container_type->GetFieldType("named");
              if (field_type->Tag() != TYPE_RECORD)
                reporter->InternalError(
                    "Unable to process 'Member__named': "
                    "Field 'named' in %s is not of type RecordType",
                    container_type->GetName().c_str());
              type = cast_intrusive<RecordType>(field_type);
            }

            const auto container = make_intrusive<RecordVal>(type);

            {
              const auto _new_src = &src->componentName;
              const auto src = _new_src;
              const auto res = convert(src);
              container->AssignField("componentName", res);
            }

            {
              const auto _new_src = src->accesst;
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
process_AlternateAccessSelection(AlternateAccessSelection_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::AlternateAccessSelection");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == AlternateAccessSelection_PR_selectAlternateAccess) {
      const auto _new_src = &src->choice.selectAlternateAccess;
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<RecordType> type = nullptr;
        if (!type) {
          auto container_type =
              cast_intrusive<RecordType>(container->GetType());
          if (!container_type->HasField("selectAlternateAccess"))
            reporter->InternalError(
                "Unable to process "
                "'AlternateAccessSelection__selectAlternateAccess': "
                "Missing field 'selectAlternateAccess' in %s",
                container_type->GetName().c_str());
          auto field_type =
              container_type->GetFieldType("selectAlternateAccess");
          if (field_type->Tag() != TYPE_RECORD)
            reporter->InternalError(
                "Unable to process "
                "'AlternateAccessSelection__selectAlternateAccess': "
                "Field 'selectAlternateAccess' in %s is not of type RecordType",
                container_type->GetName().c_str());
          type = cast_intrusive<RecordType>(field_type);
        }

        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = &src->component;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("component", res);
        }

        {
          const auto _new_src = &src->index;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("index", res);
        }

        {
          const auto _new_src = &src->indexRange;
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {

            static IntrusivePtr<RecordType> type = nullptr;
            if (!type) {
              auto container_type =
                  cast_intrusive<RecordType>(container->GetType());
              if (!container_type->HasField("indexRange"))
                reporter->InternalError(
                    "Unable to process 'selectAlternateAccess__indexRange': "
                    "Missing field 'indexRange' in %s",
                    container_type->GetName().c_str());
              auto field_type = container_type->GetFieldType("indexRange");
              if (field_type->Tag() != TYPE_RECORD)
                reporter->InternalError(
                    "Unable to process 'selectAlternateAccess__indexRange': "
                    "Field 'indexRange' in %s is not of type RecordType",
                    container_type->GetName().c_str());
              type = cast_intrusive<RecordType>(field_type);
            }

            const auto container = make_intrusive<RecordVal>(type);

            {
              const auto _new_src = &src->lowIndex;
              const auto src = _new_src;
              const auto res = convert(src);
              container->AssignField("lowIndex", res);
            }

            {
              const auto _new_src = &src->numberOfElements;
              const auto src = _new_src;
              const auto res = convert(src);
              container->AssignField("numberOfElements", res);
            }

            res = container;
          }

          container->AssignField("indexRange", res);
        }

        {
          const auto _new_src = &src->allElements;
          const auto src = _new_src;
          const auto res = true;
          container->AssignField("allElements", res);
        }

        {
          const auto _new_src = src->alternateAccess;
          const auto src = _new_src;
          const auto res = process_AlternateAccess(src);
          container->AssignField("alternateAccess", res);
        }

        res = container;
      }

      container->AssignField("selectAlternateAccess", res);
    }

    if (src->present == AlternateAccessSelection_PR_component) {
      const auto _new_src = &src->choice.component;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("component", res);
    }

    if (src->present == AlternateAccessSelection_PR_index) {
      const auto _new_src = &src->choice.index;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("index", res);
    }

    if (src->present == AlternateAccessSelection_PR_indexRange) {
      const auto _new_src = &src->choice.indexRange;
      const auto src = _new_src;
      const auto res = process_IndexRangeSeq(src);
      container->AssignField("indexRange", res);
    }

    if (src->present == AlternateAccessSelection_PR_allElements) {
      const auto _new_src = &src->choice.allElements;
      const auto src = _new_src;
      const auto res = true;
      container->AssignField("allElements", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_IndexRangeSeq(IndexRangeSeq_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::IndexRangeSeq");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = &src->lowIndex;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("lowIndex", res);
    }

    {
      const auto _new_src = &src->numberOfElements;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("numberOfElements", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ReadRequest(ReadRequest_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::ReadRequest");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src =
          src->specificationWithResult ? *src->specificationWithResult : false;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("specificationWithResult", res);
    }

    {
      const auto _new_src = &src->variableAccessSpecification;
      const auto src = _new_src;
      const auto res = process_VariableAccessSpecification(src);
      container->AssignField("variableAccessSpecification", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ReadResponse(ReadResponse_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::ReadResponse");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->variableAccessSpecification) {
      const auto _new_src = src->variableAccessSpecification;
      const auto src = _new_src;
      const auto res = process_VariableAccessSpecification(src);
      container->AssignField("variableAccessSpecification", res);
    }

    {
      const auto _new_src = &src->listOfAccessResult;
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<VectorType> type = nullptr;
        if (!type) {
          auto container_type =
              cast_intrusive<RecordType>(container->GetType());
          if (!container_type->HasField("listOfAccessResult"))
            reporter->InternalError(
                "Unable to process 'ReadResponse__listOfAccessResult': "
                "Missing field 'listOfAccessResult' in %s",
                container_type->GetName().c_str());
          auto field_type = container_type->GetFieldType("listOfAccessResult");
          if (field_type->Tag() != TYPE_VECTOR)
            reporter->InternalError(
                "Unable to process 'ReadResponse__listOfAccessResult': "
                "Field 'listOfAccessResult' in %s is not of type VectorType",
                container_type->GetName().c_str());
          type = cast_intrusive<VectorType>(field_type);
        }

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

IntrusivePtr<Val> process_WriteRequest(WriteRequest_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::WriteRequest");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = &src->variableAccessSpecification;
      const auto src = _new_src;
      const auto res = process_VariableAccessSpecification(src);
      container->AssignField("variableAccessSpecification", res);
    }

    {
      const auto _new_src = &src->listOfData;
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<VectorType> type = nullptr;
        if (!type) {
          auto container_type =
              cast_intrusive<RecordType>(container->GetType());
          if (!container_type->HasField("listOfData"))
            reporter->InternalError(
                "Unable to process 'WriteRequest__listOfData': "
                "Missing field 'listOfData' in %s",
                container_type->GetName().c_str());
          auto field_type = container_type->GetFieldType("listOfData");
          if (field_type->Tag() != TYPE_VECTOR)
            reporter->InternalError(
                "Unable to process 'WriteRequest__listOfData': "
                "Field 'listOfData' in %s is not of type VectorType",
                container_type->GetName().c_str());
          type = cast_intrusive<VectorType>(field_type);
        }

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

IntrusivePtr<Val> process_WriteResponse(WriteResponse_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<VectorType>("mms::WriteResponse");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<RecordType> type = nullptr;
        if (!type) {
          auto subtype = container->GetType()->Yield();
          if (!subtype || subtype->Tag() != TYPE_RECORD)
            reporter->InternalError(
                "Unable to process 'WriteResponse__Member': "
                "Content of %s is not of type RecordType",
                container->GetType()->GetName().c_str());
          type = cast_intrusive<RecordType>(subtype);
        }

        const auto container = make_intrusive<RecordVal>(type);

        if (src->present == WriteResponse__Member_PR_failure) {
          const auto _new_src = &src->choice.failure;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("failure", res);
        }

        if (src->present == WriteResponse__Member_PR_success) {
          const auto _new_src = &src->choice.success;
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

IntrusivePtr<Val> process_GetVariableAccessAttributesRequest(
    GetVariableAccessAttributesRequest_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetVariableAccessAttributesRequest");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == GetVariableAccessAttributesRequest_PR_name) {
      const auto _new_src = &src->choice.name;
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("name", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_GetVariableAccessAttributesResponse(
    GetVariableAccessAttributesResponse_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::GetVariableAccessAttributesResponse");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = &src->mmsDeletable;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mmsDeletable", res);
    }

    {
      const auto _new_src = &src->typeSpecification;
      const auto src = _new_src;
      const auto res = process_TypeSpecification(src);
      container->AssignField("typeSpecification", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_InformationReport(InformationReport_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::InformationReport");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = &src->variableAccessSpecification;
      const auto src = _new_src;
      const auto res = process_VariableAccessSpecification(src);
      container->AssignField("variableAccessSpecification", res);
    }

    {
      const auto _new_src = &src->listOfAccessResult;
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<VectorType> type = nullptr;
        if (!type) {
          auto container_type =
              cast_intrusive<RecordType>(container->GetType());
          if (!container_type->HasField("listOfAccessResult"))
            reporter->InternalError(
                "Unable to process 'InformationReport__listOfAccessResult': "
                "Missing field 'listOfAccessResult' in %s",
                container_type->GetName().c_str());
          auto field_type = container_type->GetFieldType("listOfAccessResult");
          if (field_type->Tag() != TYPE_VECTOR)
            reporter->InternalError(
                "Unable to process 'InformationReport__listOfAccessResult': "
                "Field 'listOfAccessResult' in %s is not of type VectorType",
                container_type->GetName().c_str());
          type = cast_intrusive<VectorType>(field_type);
        }

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

IntrusivePtr<Val>
process_DefineNamedVariableListRequest(DefineNamedVariableListRequest_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DefineNamedVariableListRequest");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = &src->variableListName;
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("variableListName", res);
    }

    {
      const auto _new_src = &src->listOfVariable;
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<VectorType> type = nullptr;
        if (!type) {
          auto container_type =
              cast_intrusive<RecordType>(container->GetType());
          if (!container_type->HasField("listOfVariable"))
            reporter->InternalError(
                "Unable to process "
                "'DefineNamedVariableListRequest__listOfVariable': "
                "Missing field 'listOfVariable' in %s",
                container_type->GetName().c_str());
          auto field_type = container_type->GetFieldType("listOfVariable");
          if (field_type->Tag() != TYPE_VECTOR)
            reporter->InternalError(
                "Unable to process "
                "'DefineNamedVariableListRequest__listOfVariable': "
                "Field 'listOfVariable' in %s is not of type VectorType",
                container_type->GetName().c_str());
          type = cast_intrusive<VectorType>(field_type);
        }

        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_VariableDef(src);
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

IntrusivePtr<Val> process_GetNamedVariableListAttributesRequest(
    GetNamedVariableListAttributesRequest_t *src) {
  const auto res = process_ObjectName(src);
  return res;
}

IntrusivePtr<Val> process_GetNamedVariableListAttributesResponse(
    GetNamedVariableListAttributesResponse_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>(
        "mms::GetNamedVariableListAttributesResponse");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = &src->mmsDeletable;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mmsDeletable", res);
    }

    {
      const auto _new_src = &src->listOfVariable;
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<VectorType> type = nullptr;
        if (!type) {
          auto container_type =
              cast_intrusive<RecordType>(container->GetType());
          if (!container_type->HasField("listOfVariable"))
            reporter->InternalError(
                "Unable to process "
                "'GetNamedVariableListAttributesResponse__listOfVariable': "
                "Missing field 'listOfVariable' in %s",
                container_type->GetName().c_str());
          auto field_type = container_type->GetFieldType("listOfVariable");
          if (field_type->Tag() != TYPE_VECTOR)
            reporter->InternalError(
                "Unable to process "
                "'GetNamedVariableListAttributesResponse__listOfVariable': "
                "Field 'listOfVariable' in %s is not of type VectorType",
                container_type->GetName().c_str());
          type = cast_intrusive<VectorType>(field_type);
        }

        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_VariableDef(src);
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

IntrusivePtr<Val>
process_DeleteNamedVariableListRequest(DeleteNamedVariableListRequest_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DeleteNamedVariableListRequest");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = src->scopeOfDelete;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("scopeOfDelete", res);
    }

    if (src->listOfVariableListName) {
      const auto _new_src = src->listOfVariableListName;
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<VectorType> type = nullptr;
        if (!type) {
          auto container_type =
              cast_intrusive<RecordType>(container->GetType());
          if (!container_type->HasField("listOfVariableListName"))
            reporter->InternalError(
                "Unable to process "
                "'DeleteNamedVariableListRequest__listOfVariableListName': "
                "Missing field 'listOfVariableListName' in %s",
                container_type->GetName().c_str());
          auto field_type =
              container_type->GetFieldType("listOfVariableListName");
          if (field_type->Tag() != TYPE_VECTOR)
            reporter->InternalError(
                "Unable to process "
                "'DeleteNamedVariableListRequest__listOfVariableListName': "
                "Field 'listOfVariableListName' in %s is not of type "
                "VectorType",
                container_type->GetName().c_str());
          type = cast_intrusive<VectorType>(field_type);
        }

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
      const auto _new_src = src->domainName;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("domainName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_DeleteNamedVariableListResponse(
    DeleteNamedVariableListResponse_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::DeleteNamedVariableListResponse");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = &src->numberMatched;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("numberMatched", res);
    }

    {
      const auto _new_src = &src->numberDeleted;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("numberDeleted", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_AccessResult(AccessResult_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::AccessResult");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == AccessResult_PR_failure) {
      const auto _new_src = &src->choice.failure;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("failure", res);
    }

    if (src->present == AccessResult_PR_success) {
      const auto _new_src = &src->choice.success;
      const auto src = _new_src;
      const auto res = process_Data(src);
      container->AssignField("success", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Data(Data_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::Data");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == Data_PR_array) {
      const auto _new_src = src->choice.array;
      const auto src = _new_src;
      const auto res = process_DataSequence(src);
      container->AssignField("array", res);
    }

    if (src->present == Data_PR_structure) {
      const auto _new_src = src->choice.structure;
      const auto src = _new_src;
      const auto res = process_DataSequence(src);
      container->AssignField("structure", res);
    }

    if (src->present == Data_PR_boolean) {
      const auto _new_src = &src->choice.boolean;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("boolean", res);
    }

    if (src->present == Data_PR_bitString) {
      const auto _new_src = &src->choice.bitString;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("bitString", res);
    }

    if (src->present == Data_PR_integer) {
      const auto _new_src = &src->choice.integer;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("integer", res);
    }

    if (src->present == Data_PR_unsigned) {
      const auto _new_src = &src->choice.Unsigned;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("unsigned", res);
    }

    if (src->present == Data_PR_floatingPoint) {
      const auto _new_src = &src->choice.floatingPoint;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("floatingPoint", res);
    }

    if (src->present == Data_PR_octetString) {
      const auto _new_src = &src->choice.octetString;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("octetString", res);
    }

    if (src->present == Data_PR_visibleString) {
      const auto _new_src = &src->choice.visibleString;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("visibleString", res);
    }

    if (src->present == Data_PR_binaryTime) {
      const auto _new_src = &src->choice.binaryTime;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("binaryTime", res);
    }

    if (src->present == Data_PR_mmsString) {
      const auto _new_src = &src->choice.mmsString;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mmsString", res);
    }

    if (src->present == Data_PR_utcTime) {
      const auto _new_src = &src->choice.utcTime;
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("utcTime", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_DataSequence(DataSequence_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<VectorType>("mms::DataSequence");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;
      const auto res = process_Data(src);
      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_VariableAccessSpecification(VariableAccessSpecification_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::VariableAccessSpecification");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == VariableAccessSpecification_PR_listOfVariable) {
      const auto _new_src = &src->choice.listOfVariable;
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {

        static IntrusivePtr<VectorType> type = nullptr;
        if (!type) {
          auto container_type =
              cast_intrusive<RecordType>(container->GetType());
          if (!container_type->HasField("listOfVariable"))
            reporter->InternalError(
                "Unable to process "
                "'VariableAccessSpecification__listOfVariable': "
                "Missing field 'listOfVariable' in %s",
                container_type->GetName().c_str());
          auto field_type = container_type->GetFieldType("listOfVariable");
          if (field_type->Tag() != TYPE_VECTOR)
            reporter->InternalError(
                "Unable to process "
                "'VariableAccessSpecification__listOfVariable': "
                "Field 'listOfVariable' in %s is not of type VectorType",
                container_type->GetName().c_str());
          type = cast_intrusive<VectorType>(field_type);
        }

        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_VariableDef(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("listOfVariable", res);
    }

    if (src->present == VariableAccessSpecification_PR_variableListName) {
      const auto _new_src = &src->choice.variableListName;
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("variableListName", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_VariableDef(VariableDef_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("mms::VariableDef");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = &src->variableSpecification;
      const auto src = _new_src;
      const auto res = process_VariableSpecification(src);
      container->AssignField("variableSpecification", res);
    }

    if (src->alternateAccess) {
      const auto _new_src = src->alternateAccess;
      const auto src = _new_src;
      const auto res = process_AlternateAccess(src);
      container->AssignField("alternateAccess", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_VariableSpecification(VariableSpecification_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("mms::VariableSpecification");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == VariableSpecification_PR_name) {
      const auto _new_src = &src->choice.name;
      const auto src = _new_src;
      const auto res = process_ObjectName(src);
      container->AssignField("name", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_ScatteredAccessDescription(ScatteredAccessDescription_t *src) {
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

        static IntrusivePtr<RecordType> type = nullptr;
        if (!type) {
          auto subtype = container->GetType()->Yield();
          if (!subtype || subtype->Tag() != TYPE_RECORD)
            reporter->InternalError(
                "Unable to process 'ScatteredAccessDescription__Member': "
                "Content of %s is not of type RecordType",
                container->GetType()->GetName().c_str());
          type = cast_intrusive<RecordType>(subtype);
        }

        const auto container = make_intrusive<RecordVal>(type);

        if (src->componentName) {
          const auto _new_src = src->componentName;
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("componentName", res);
        }

        {
          const auto _new_src = &src->variableSpecification;
          const auto src = _new_src;
          const auto res = process_VariableSpecification(src);
          container->AssignField("variableSpecification", res);
        }

        if (src->alternateAccess) {
          const auto _new_src = src->alternateAccess;
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

} // namespace zeek::plugin::mms
