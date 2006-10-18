require File.dirname(__FILE__) + '/test_helper.rb'

require 'snmp/agent'

class SNMP::Agent
	public :process_get_request, :process_get_next_request
end

class SnmpProtocolTest < Test::Unit::TestCase
	def setup
		@a = SNMP::Agent.new
		
		class << @a
			public :process_get_request, :process_get_next_request
		end
	end
	
	def test_single_get
		@a.add_plugin('1.2.3') { 42 }
		
		pdu = SNMP::GetRequest.new(1, SNMP::VarBindList.new('1.2.3'))
		msg = SNMP::Message.new(1, 'public', pdu)
		
		resp = @a.process_get_request(msg)
		
		assert_equal(SNMP::Message, resp.class)
		assert_equal(1, resp.pdu.varbind_list.length)
		assert_equal("INTEGER", resp.pdu.varbind_list[0].value.asn1_type)
		assert_equal(42, resp.pdu.varbind_list[0].value.to_i)
	end
	
	def test_no_such_object
		@a.add_plugin('1.2.3') { 42 }
		
		pdu = SNMP::GetRequest.new(1, SNMP::VarBindList.new('1.2.3.4'))
		msg = SNMP::Message.new(1, 'public', pdu)
		
		resp = @a.process_get_request(msg)
		
		assert_equal(SNMP::Message, resp.class)
		assert_equal(1, resp.pdu.varbind_list.length)
		assert_equal(SNMP::NoSuchObject, resp.pdu.varbind_list[0].value)
	end

	def test_multi_get_request
		@a.add_plugin('1.2.3') { 42 }
		
		pdu = SNMP::GetRequest.new(1, SNMP::VarBindList.new(['1.3.6.1', '1.2.3', '1.2.3.4']))
		msg = SNMP::Message.new(1, 'public', pdu)
		
		resp = @a.process_get_request(msg)
		
		assert_equal(SNMP::Message, resp.class)
		assert_equal(3, resp.pdu.varbind_list.length)
		assert_equal(SNMP::NoSuchObject, resp.pdu.varbind_list[0].value)
		assert_equal(42, resp.pdu.varbind_list[1].value.to_i)
		assert_equal(SNMP::NoSuchObject, resp.pdu.varbind_list[2].value)
	end

	def test_get_next_request
		@a.add_plugin('3.2.1') { [1, 1, 2, 3, 5, 8, 13] }
		
		pdu = SNMP::GetNextRequest.new(1, SNMP::VarBindList.new(['3.2.1', '3.2.1.4', '3.2.1.6']))
		msg = SNMP::Message.new(1, 'public', pdu)
		
		resp = @a.process_get_next_request(msg)
		
		assert_equal(SNMP::Message, resp.class)
		assert_equal(3, resp.pdu.varbind_list.length)
		assert_equal('3.2.1.0', resp.pdu.varbind_list[0].name.to_s)
		assert_equal(1, resp.pdu.varbind_list[0].value.to_i)
		assert_equal('3.2.1.5', resp.pdu.varbind_list[1].name.to_s)
		assert_equal(8, resp.pdu.varbind_list[1].value.to_i)
		assert_equal(:noSuchName, resp.pdu.error_status)
		assert_equal(2, resp.pdu.error_index)
	end

	def test_exceptional_plugin
		@a.add_plugin('1.2.3') { raise "Broooooken!" }
		
		pdu = SNMP::GetRequest.new(1, SNMP::VarBindList.new('1.2.3.4'))
		msg = SNMP::Message.new(1, 'public', pdu)
		
		resp = @a.process_get_request(msg)
		
		assert_equal(SNMP::Message, resp.class)
		assert_equal(1, resp.pdu.varbind_list.length)
		assert_equal(SNMP::NoSuchObject, resp.pdu.varbind_list[0].value)
	end
end
