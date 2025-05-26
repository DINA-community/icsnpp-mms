# @TEST-EXEC: zeek -NN OSS::MMS |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
