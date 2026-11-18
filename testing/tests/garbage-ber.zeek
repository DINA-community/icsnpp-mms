# @TEST-DOC: Exercise the MMS analyzer with 200 garbage BER PDUs inside a valid TPKT/COTP/SESS/PRES/ACSE/MMS association. The test checks that Zeek exits successfully and reports at least one mms_parse_error
# @TEST-EXEC: zeek -C -r ${TRACES}/garbage-ber.pcap ${PACKAGE} %INPUT >output 2>&1
# @TEST-EXEC: grep -q mms_parse_error weird.log

event zeek_init() &priority=5
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_TPKT, 102/tcp);
	}
