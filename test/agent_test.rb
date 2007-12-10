require File.dirname(__FILE__) + '/test_helper.rb'

require 'snmp/agent'

class SnmpAgentTest < Test::Unit::TestCase
	def test_custom_sys_values
		port = 50000 + rand(10000)
		@a = SNMP::Agent.new(:port => port,
		                     :sysContact => 'sysContact',
		                     :sysName => 'sysName',
		                     :sysLocation => 'sysLocation'
		                    )
		                    
		runner = Thread.new { @a.start }
		
		m = SNMP::Manager.new(:Host => 'localhost',
		                      :Port => port,
		                      :Retries => 1)

		res = m.get(['1.3.6.1.2.1.1.4.0', '1.3.6.1.2.1.1.5.0', '1.3.6.1.2.1.1.6.0'])
		
		assert_equal 'sysContact', res.varbind_list[0].value.to_s
		assert_equal 'sysName', res.varbind_list[1].value.to_s
		assert_equal 'sysLocation', res.varbind_list[2].value.to_s
		
		@a.shutdown
	end
end
