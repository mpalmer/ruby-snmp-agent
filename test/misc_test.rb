require File.dirname(__FILE__) + '/test_helper.rb'

require 'snmp/agent'

class MiscTest < Test::Unit::TestCase
	def test_array_to_hash
		assert_equal({0 => 'a', 1 => 'b', 2 => 'c', 3 => 'd', 4 => 'e'}, %w{a b c d e}.to_hash)
	end
end
