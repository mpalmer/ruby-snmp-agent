require File.dirname(__FILE__) + '/test_helper.rb'

require 'snmp/agent'

class CoreTest < Test::Unit::TestCase
	def test_single_get
		a = SNMP::Agent.new
		
		a.add_plugin('1.2.3') { 42 }
		
		pdu = SNMP::GetRequest.new(1, SNMP::VarBindList.new('1.2.3'))
		msg = SNMP::Message.new(1, 'public', pdu)
		
		resp = a.process_get_request(msg)
		
		assert_equal(SNMP::Message, resp.class)
		assert_equal(1, resp.pdu.varbind_list.length)
		assert_equal("INTEGER", resp.pdu.varbind_list[0].value.asn1_type)
		assert_equal(42, resp.pdu.varbind_list[0].value.to_i)
	end
	
	def test_no_such_object
		a = SNMP::Agent.new
		
		a.add_plugin('1.2.3') { 42 }
		
		pdu = SNMP::GetRequest.new(1, SNMP::VarBindList.new('1.2.3.4'))
		msg = SNMP::Message.new(1, 'public', pdu)
		
		resp = a.process_get_request(msg)
		
		assert_equal(SNMP::Message, resp.class)
		assert_equal(1, resp.pdu.varbind_list.length)
		assert_equal(SNMP::NoSuchObject, resp.pdu.varbind_list[0].value.class)
	end

	def test_multi_get_request
		a = SNMP::Agent.new
		
		a.add_plugin('1.2.3') { 42 }
		
		pdu = SNMP::GetRequest.new(1, SNMP::VarBindList.new(['1.3.6.1', '1.2.3', '1.2.3.4']))
		msg = SNMP::Message.new(1, 'public', pdu)
		
		resp = a.process_get_request(msg)
		
		assert_equal(SNMP::Message, resp.class)
		assert_equal(3, resp.pdu.varbind_list.length)
		assert_equal(SNMP::NoSuchObject, resp.pdu.varbind_list[0].value.class)
		assert_equal(42, resp.pdu.varbind_list[1].value.to_i)
		assert_equal(SNMP::NoSuchObject, resp.pdu.varbind_list[2].value.class)
	end
	
	# This is where things get *really* tricky
#	def test_get_next_request
#		a = SNMP::Agent.new
#		
#		a.add_plugin('1.2.3') { [1, 1, 2, 3, 5, 8, 13] }
#		
#		pdu = SNMP::GetNextRequest.new(1, SNMP::VarBindList.new(['1.2.3', '1.2.3.4']))
#		msg = SNMP::Message.new(1, 'public', pdu)
#		
#		resp = a.process_get_next_request(msg)
#		
#		assert_equal(SNMP::Message, resp.class)
#		assert_equal(2, resp.pdu.varbind_list.length)
#		assert_equal('1.2.3.0', resp.pdu.varbind_list[0].name.to_s)
#		assert_equal(1, resp.pdu.varbind_list[0].value.to_i)
#		assert_equal('1.2.3.5', resp.pdu.varbind_list[1].name.to_s)
#		assert_equal(8, resp.pdu.varbind_list[0].value.to_i)
#	end
end
