# @TEST-DOC: A write to the named variable list IED1DataSet (vmd-specific) must raise VariableListWriteRequest.
# @TEST-EXEC: zeek -C -r ${TRACES}/varlist-write.pcap ${PACKAGE} %INPUT >output 2>&1
# @TEST-EXEC: grep -q 'VariableListWriteRequest.*IED1DataSet' output
# @TEST-EXEC: test ! -f reporter.log

event zeek_init() &priority=5
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_TPKT, 102/tcp);
	}

event mms::VariableListWriteRequest(c: connection, listname: mms::ObjectName, data: mms::Data)
	{
	print "VariableListWriteRequest", listname;
	}
