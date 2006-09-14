require File.dirname(__FILE__) + '/test_helper.rb'

require 'snmp/agent'

class MibNodeTest < Test::Unit::TestCase
	def test_elementary_creation
		n = SNMP::MibNode.new
		
		assert_equal(SNMP::MibNode, n.class)
		assert_equal(0, n.length)
		assert_equal([], n.keys)
		
		n = SNMP::MibNode.new({0 => 1, 1 => 2, 2 => 3})
		assert_equal(3, n.length)
		assert_equal([0, 1, 2], n.keys.sort)
		assert_equal(1, n[0])
		assert_equal(2, n[1])
		assert_equal(3, n[2])

		n = SNMP::MibNode.new([1, 2, 3])
		assert_equal(3, n.length)
		assert_equal([0, 1, 2], n.keys.sort)
		assert_equal(1, n[0])
		assert_equal(2, n[1])
		assert_equal(3, n[2])
		
		n = SNMP::MibNode.new({1 => 1, 2 => 3, 5 => 8, 13 => 21})
		assert_equal(4, n.length)
		assert_equal([1, 2, 5, 13], n.keys.sort)
		assert_equal(1, n[1])
		assert_equal(3, n[2])
		assert_equal(8, n[5])
		assert_equal(21, n[13])
		assert_equal(nil, n[0])
	end

	def test_more_interesting_creation
		n = SNMP::MibNode.new({0 => [0, 0, 0, 0], 1 => [0, 1, 2, 3], 2 => [0, 2, 4, 6], 4 => [0, 4, 8, 12]})
		
		assert_equal(4, n.length)
		assert_equal([0, 1, 2, 4], n.keys.sort)
		
		n_ = n[2]
		assert_equal(SNMP::MibNode, n_.class)
		assert_equal([0, 1, 2, 3], n_.keys.sort)
		assert_equal(4, n_[2])
	end

	def test_now_with_added_proc
		n = SNMP::MibNode.new({2 => Proc.new { 42 }})
		
		assert_equal(1, n.length)
		assert_equal([2], n.keys)
		assert_equal(42, n.get_node([2]))

		n = SNMP::MibNode.new({2 => Proc.new {[42]}})
		assert_equal(SNMP::MibNode, n.get_node([2]).class)
		assert_equal(Proc, n[2].class)
		assert_equal(42, n.get_node('2.0'))
		assert_equal(nil, n.get_node('2.1'))
	end
	
	def test_with_noninteger_keys
		assert_raise(ArgumentError) { SNMP::MibNode.new({'xyzzy' => 42}) }
	end

	def test_get_node
		n = SNMP::MibNode.new(1 => {2 => {3 => [0, 1, 2, 3, 4]}})
		
		n_ = n.get_node(SNMP::ObjectId.new('1.2'))
		assert_equal(SNMP::MibNode, n_.class)
		assert_equal([3], n_.keys)
		n__ = n_[3]
		assert_equal(SNMP::MibNode, n__.class)
		assert_equal([0, 1, 2, 3, 4], n__.keys)
	end
	
	def test_get_node_through_proc
		n = SNMP::MibNode.new(1 => {2 => {3 => Proc.new {[[0, 1, 2], [10, 11, 12], [20, 21, 22]]}}})
		
		n_ = n.get_node(SNMP::ObjectId.new('1.2.3.1'))
		assert_equal(SNMP::MibNode, n_.class)
		assert_equal([0, 1, 2], n_.keys)
		assert_equal(11, n_[1])
	end

	def test_get_node_bomb_on_plugin
		n = SNMP::MibNode.new(1 => {2 => {3 => Proc.new {[0, 1, 2]}}})
		h = {1 => {2 => {3 => Proc.new {[0, 1, 2]}}}}

		assert_raise(SNMP::TraversesPluginError) { n.get_node('1.2.3.0', :allow_plugins => false) }
	end

	def test_make_it_as_we_walk_it
		n = SNMP::MibNode.new(1 => {2 => {3 => [0, 1, 2, 3]}})
		
		assert_equal(nil, n.get_node('3.2.3.5'))
		n_ = n.get_node('3.2.3.5', :make_new_nodes => true)
		assert_equal(SNMP::MibNode, n_.class)
		assert_equal(0, n_.length)
	end
end
