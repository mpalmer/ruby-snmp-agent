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

	def test_single_community_restriction
		port = 50000 + rand(10000)
		@a = SNMP::Agent.new(:port => port, :community => 'privateparts')
		@a.add_plugin('1.2.3') { [1, 2, 3] }
		
		runner = Thread.new { @a.start }
		
		m = SNMP::Manager.new(:Host => 'localhost',
		                      :Port => port,
		                      :Community => 'privateparts',
		                      :Retries => 1)
		assert_nothing_raised { m.get(['1.2.3.1']) }

		m = SNMP::Manager.new(:Host => 'localhost',
		                      :Port => port,
		                      :Community => 'somethingfunny',
		                      :Retries => 1,
		                      :Timeout => 0.1)

		assert_raise(SNMP::RequestTimeout) { m.get(['1.2.3.1']) }
		
		@a.shutdown
	end

	def test_array_of_communities
		port = 50000 + rand(10000)
		@a = SNMP::Agent.new(:port => port, :community => ['private', 'parts'])
		@a.add_plugin('1.2.3') { [1, 2, 3] }
		
		runner = Thread.new { @a.start }
		
		m = SNMP::Manager.new(:Host => 'localhost',
		                      :Port => port,
		                      :Community => 'private',
		                      :Retries => 1)
		assert_nothing_raised { m.get(['1.2.3.1']) }

		m = SNMP::Manager.new(:Host => 'localhost',
		                      :Port => port,
		                      :Community => 'somethingfunny',
		                      :Retries => 1,
		                      :Timeout => 0.1)

		assert_raise(SNMP::RequestTimeout) { m.get(['1.2.3.1']) }
		
		@a.shutdown
	end

	def test_get_next_request_against_single_value_plugin
		@a.add_plugin('3.2.1') { 42 }
		
		pdu = SNMP::GetNextRequest.new(1, SNMP::VarBindList.new(['3.2']))
		msg = SNMP::Message.new(1, 'public', pdu)
		
		resp = @a.process_get_next_request(msg)
		
		assert_equal(SNMP::Message, resp.class)
		assert_equal(1, resp.pdu.varbind_list.length)
		assert_equal('3.2.1', resp.pdu.varbind_list[0].name.to_s)
		assert_equal(42, resp.pdu.varbind_list[0].value.to_i)
	end

	def test_get_next_request_with_crazy_data_structure
		@a.add_plugin('27068.2.2.7') do
			{1 => [0, 1, 2],
			 2 => ['fairfax/YSM_US', 'fengmingxuan/netease', '58.com/baidu'],
			 3 => [437, 752, 0],
			 4 => [437, 752, 0],
			 5 => [437, 752, 0],
			 6 => [1, 1, 0],
			 7 => [1171334642, 1171334641, 1171334640],
			 8 => [],
			 9 => [],
			 10 => [],
			 11 => [1, 1, 1],
			 12 => [0, 0, 1],
			 13 => ['fairfax', 'fengmingxuan', '58.com'],
			 14 => ['YSM_US', 'netease', 'baidu']
			}
		end
		
		# First up, one we think is a no-brainer to work
		pdu = SNMP::GetNextRequest.new(1, SNMP::VarBindList.new(['27068.2.2.7.6.2']))
		msg = SNMP::Message.new(1, 'public', pdu)
		
		resp = @a.process_get_next_request(msg)
		
		assert_equal(SNMP::Message, resp.class)
		assert_equal(1, resp.pdu.varbind_list.length)
		assert_equal('27068.2.2.7.7.0', resp.pdu.varbind_list[0].name.to_s)
		assert_equal(1171334642, resp.pdu.varbind_list[0].value.to_i)

		# Now one that's a bit trickier.  The bug that we've seen is that the
		# system appears to not walk over empty arrays properly when performing
		# the GetNext operation.
		pdu = SNMP::GetNextRequest.new(1, SNMP::VarBindList.new(['27068.2.2.7.7.2']))
		msg = SNMP::Message.new(1, 'public', pdu)
		
		resp = @a.process_get_next_request(msg)
		
		assert_equal(SNMP::Message, resp.class)
		assert_equal(1, resp.pdu.varbind_list.length)
		assert_equal('27068.2.2.7.11.0', resp.pdu.varbind_list[0].name.to_s)
		assert_equal(1, resp.pdu.varbind_list[0].value.to_i)
	end

	def test_passing_the_community_into_the_plugin
		@a.add_plugin('1.2.3') { |community| community }
		
		pdu = SNMP::GetRequest.new(1, SNMP::VarBindList.new('1.2.3'))
		msg = SNMP::Message.new(1, 'public', pdu)
		
		resp = @a.process_get_request(msg)
		
		assert_equal(SNMP::Message, resp.class)
		assert_equal(1, resp.pdu.varbind_list.length)
		assert_equal("OCTET STRING", resp.pdu.varbind_list[0].value.asn1_type)
		assert_equal('public', resp.pdu.varbind_list[0].value.to_s)
	end
end
