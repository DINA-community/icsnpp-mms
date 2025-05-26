/* THIS CODE IS GENERATED. DON'T CHANGE MANUALLY! */

#pragma once

#include "zeek/Val.h"
#include <AccessResult.h>
#include <AlternateAccess.h>
#include <AlternateAccessSelection.h>
#include <ConfirmedRequestPdu.h>
#include <ConfirmedResponsePdu.h>
#include <ConfirmedServiceRequest.h>
#include <ConfirmedServiceResponse.h>
#include <Data.h>
#include <DataSequence.h>
#include <DefineNamedVariableListRequest.h>
#include <DeleteNamedVariableListRequest.h>
#include <DeleteNamedVariableListResponse.h>
#include <GetNameListRequest.h>
#include <GetNameListResponse.h>
#include <GetNamedVariableListAttributesRequest.h>
#include <GetNamedVariableListAttributesResponse.h>
#include <GetVariableAccessAttributesRequest.h>
#include <GetVariableAccessAttributesResponse.h>
#include <IndexRangeSeq.h>
#include <InformationReport.h>
#include <InitRequestDetail.h>
#include <InitResponseDetail.h>
#include <InitiateErrorPdu.h>
#include <InitiateRequestPdu.h>
#include <InitiateResponsePdu.h>
#include <MmsPdu.h>
#include <ObjectClass.h>
#include <ObjectName.h>
#include <ParameterSupportOptions.h>
#include <ReadRequest.h>
#include <ReadResponse.h>
#include <ScatteredAccessDescription.h>
#include <ServiceError.h>
#include <ServiceSupportOptions.h>
#include <StructComponent.h>
#include <TypeSpecification.h>
#include <UnconfirmedPDU.h>
#include <UnconfirmedService.h>
#include <VariableAccessSpecification.h>
#include <VariableDef.h>
#include <VariableSpecification.h>
#include <WriteRequest.h>
#include <WriteResponse.h>

using namespace zeek;

namespace zeek::plugin::mms {

IntrusivePtr<Val> process_MmsPdu(MmsPdu_t *src);
IntrusivePtr<Val> process_UnconfirmedPDU(UnconfirmedPDU_t *src);
IntrusivePtr<Val> process_UnconfirmedService(UnconfirmedService_t *src);
IntrusivePtr<Val> process_ConfirmedRequestPdu(ConfirmedRequestPdu_t *src);
IntrusivePtr<Val> process_ConfirmedResponsePdu(ConfirmedResponsePdu_t *src);
IntrusivePtr<Val>
process_ConfirmedServiceRequest(ConfirmedServiceRequest_t *src);
IntrusivePtr<Val>
process_ConfirmedServiceResponse(ConfirmedServiceResponse_t *src);
IntrusivePtr<Val> process_ObjectName(ObjectName_t *src);
IntrusivePtr<Val> process_InitiateErrorPdu(InitiateErrorPdu_t *src);
IntrusivePtr<Val> process_InitiateRequestPdu(InitiateRequestPdu_t *src);
IntrusivePtr<Val> process_InitRequestDetail(InitRequestDetail_t *src);
IntrusivePtr<Val> process_InitiateResponsePdu(InitiateResponsePdu_t *src);
IntrusivePtr<Val> process_InitResponseDetail(InitResponseDetail_t *src);
IntrusivePtr<Val>
process_ParameterSupportOptions(ParameterSupportOptions_t *src);
IntrusivePtr<Val> process_ServiceSupportOptions(ServiceSupportOptions_t *src);
IntrusivePtr<Val> process_ServiceError(ServiceError_t *src);
IntrusivePtr<Val> process_GetNameListRequest(GetNameListRequest_t *src);
IntrusivePtr<Val> process_ObjectClass(ObjectClass_t *src);
IntrusivePtr<Val> process_GetNameListResponse(GetNameListResponse_t *src);
IntrusivePtr<Val> process_TypeSpecification(TypeSpecification_t *src);
IntrusivePtr<Val> process_StructComponent(StructComponent_t *src);
IntrusivePtr<Val> process_AlternateAccess(AlternateAccess_t *src);
IntrusivePtr<Val>
process_AlternateAccessSelection(AlternateAccessSelection_t *src);
IntrusivePtr<Val> process_IndexRangeSeq(IndexRangeSeq_t *src);
IntrusivePtr<Val> process_ReadRequest(ReadRequest_t *src);
IntrusivePtr<Val> process_ReadResponse(ReadResponse_t *src);
IntrusivePtr<Val> process_WriteRequest(WriteRequest_t *src);
IntrusivePtr<Val> process_WriteResponse(WriteResponse_t *src);
IntrusivePtr<Val> process_GetVariableAccessAttributesRequest(
    GetVariableAccessAttributesRequest_t *src);
IntrusivePtr<Val> process_GetVariableAccessAttributesResponse(
    GetVariableAccessAttributesResponse_t *src);
IntrusivePtr<Val> process_InformationReport(InformationReport_t *src);
IntrusivePtr<Val>
process_DefineNamedVariableListRequest(DefineNamedVariableListRequest_t *src);
IntrusivePtr<Val> process_GetNamedVariableListAttributesRequest(
    GetNamedVariableListAttributesRequest_t *src);
IntrusivePtr<Val> process_GetNamedVariableListAttributesResponse(
    GetNamedVariableListAttributesResponse_t *src);
IntrusivePtr<Val>
process_DeleteNamedVariableListRequest(DeleteNamedVariableListRequest_t *src);
IntrusivePtr<Val>
process_DeleteNamedVariableListResponse(DeleteNamedVariableListResponse_t *src);
IntrusivePtr<Val> process_AccessResult(AccessResult_t *src);
IntrusivePtr<Val> process_Data(Data_t *src);
IntrusivePtr<Val> process_DataSequence(DataSequence_t *src);
IntrusivePtr<Val>
process_VariableAccessSpecification(VariableAccessSpecification_t *src);
IntrusivePtr<Val> process_VariableDef(VariableDef_t *src);
IntrusivePtr<Val> process_VariableSpecification(VariableSpecification_t *src);
IntrusivePtr<Val>
process_ScatteredAccessDescription(ScatteredAccessDescription_t *src);

} // namespace zeek::plugin::mms
