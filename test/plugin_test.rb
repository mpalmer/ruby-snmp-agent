require File.dirname(__FILE__) + '/test_helper.rb'

require 'snmp/agent'

class PluginInterfaceTest < Test::Unit::TestCase
	def test_trivial_plugin
		a = SNMP::Agent.new
		
		a.add_plugin('1.2.3') { 42 }
		
		assert_equal(42, a.get_raw_value_from_plugin('1.2.3'))
	end

	def test_almost_as_trivial_plugin
		a = SNMP::Agent.new
		
		a.add_plugin('1.2.3') { [42] }
		
		assert_equal(nil, a.get_raw_value_from_plugin('1.2.3'))
		assert_equal(42, a.get_raw_value_from_plugin('1.2.3.0'))
	end

	def test_a_set_of_data
		a = SNMP::Agent.new
		
		a.add_plugin('1.2.3') { [0, 1, 2, 3, 4, 5] }
		
		assert_equal(nil, a.get_raw_value_from_plugin('1.2.3'))
		6.times { |v| assert_equal(v, a.get_raw_value_from_plugin("1.2.3.#{v}")) }
	end

	def test_a_tree_of_data
		a = SNMP::Agent.new
		
		a.add_plugin('1.2.3') { [[11, 12, 13], [21, 22, 23], [31, 32, 33]] }

		assert_equal(nil, a.get_raw_value_from_plugin('1.2.3'))
		assert_equal(nil, a.get_raw_value_from_plugin('1.2.3.0'))
		
		3.times { |i|
			3.times { |j|
				assert_equal("#{i+1}#{j+1}".to_i, a.get_raw_value_from_plugin("1.2.3.#{i}.#{j}"))
			}
		}
	end

	def test_a_bridge_too_far
		a = SNMP::Agent.new
		
		a.add_plugin('1.2.3') { [0, 1, 2] }
		
		# Fails because we don't have .1.2.3.4
		assert_equal(nil, a.get_raw_value_from_plugin('1.2.3.4'))
		
		# Fails because we don't have a subtree from .1.2.3.1
		assert_equal(nil, a.get_raw_value_from_plugin('1.2.3.1.0'))
	end

=begin
	def test_next_oid_in_tree
		a = SNMP::Agent.new :logger => Logger.new(STDOUT)
		
		a.add_plugin('1') { [nil, %w{the quick brown etc}] }
		a.add_plugin('1.2.3') { [0, 1, 2] }
		a.add_plugin('4.5.6') { [5, 6, 7] }
		
		# Simple case -- delve into the tree in the same plugin
		assert_equal('1.2.3.0', a.next_oid_in_tree('1.2.3').to_s)
		
		# Slightly harder -- find the first real value in the next tree
		assert_equal('1.2.3.0', a.next_oid_in_tree('1.2').to_s)
		
		# Find when between jobs
		assert_equal('4.5.6.0', a.next_oid_in_tree('2.3.4.5.6.78').to_s)
		
		# What about when we're off the end of the tree?
		assert_equal(SNMP::EndOfMibView, a.next_oid_in_tree('5').class)
	end
=end
end
