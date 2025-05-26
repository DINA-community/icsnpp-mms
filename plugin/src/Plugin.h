#pragma once

#include <zeek/plugin/Plugin.h>

namespace zeek::plugin::mms {

constexpr const char* MMS_PDU_EVENT="mms::mms_pdu";

class Plugin : public zeek::plugin::Plugin
{
protected:
	Configuration Configure() override;
    void InitPreScript() override;
};

} // namespace zeek::analyzer::mms
