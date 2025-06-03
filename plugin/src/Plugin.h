#pragma once

#include <zeek/plugin/Plugin.h>

namespace zeek::plugin::mms {

class Plugin : public zeek::plugin::Plugin
{
protected:
	Configuration Configure() override;
};

} // namespace zeek::analyzer::mms
