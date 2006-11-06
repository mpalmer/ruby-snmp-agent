require File.dirname(__FILE__) + '/test_helper.rb'

require 'tmpdir'
require 'fileutils'
require 'snmp/agent'

class PluginInterfaceTest < Test::Unit::TestCase
	def setup
		@a = SNMP::Agent.new
		
		class << @a
			public :get_mib_entry, :get_snmp_value, :next_oid_in_tree
		end
	end
	
	def test_trivial_plugin
		@a.add_plugin('1.2.3') { 42 }
		
		assert_equal(42, @a.get_mib_entry('1.2.3'))

		# Special check to make sure that get_mib_entry doesn't
		# mangle the OID passed in
		oid = SNMP::ObjectId.new('1.2.3')
		assert_equal(42, @a.get_mib_entry(oid))
		assert_equal(SNMP::ObjectId, oid.class)
		assert_equal('1.2.3', oid.to_s)
	end

	def test_almost_as_trivial_plugin
		@a.add_plugin('1.2.3') { [42] }
		
		assert_equal({0=>42}, @a.get_mib_entry('1.2.3').to_hash)
		assert_equal(SNMP::NoSuchObject, @a.get_snmp_value('1.2.3'))
		assert_equal(42, @a.get_mib_entry('1.2.3.0'))
	end

	def test_a_set_of_data
		@a.add_plugin('1.2.3') { [0, 1, 2, 3, 4, 5] }
		
		assert_equal({0=>0,1=>1,2=>2,3=>3,4=>4,5=>5}, @a.get_mib_entry('1.2.3').to_hash)
		assert_equal(SNMP::NoSuchObject, @a.get_snmp_value('1.2.3'))
		6.times { |v| assert_equal(v, @a.get_mib_entry("1.2.3.#{v}")) }
	end

	def test_multiple_plugins
		@a.add_plugin('1.1') { [nil, %w{the quick brown etc}] }
		@a.add_plugin('1.2.3') { [0, 1, 2] }
		@a.add_plugin('4.5.6') { [5, 6, 7] }

		assert_equal({0 => nil, 1 => {0=>'the', 1=>'quick', 2=>'brown', 3=>'etc'}},
		             @a.get_mib_entry('1.1').to_hash)
		assert_equal(nil, @a.get_mib_entry('1.1.0'))
		assert_equal('brown', @a.get_mib_entry('1.1.1.2'))
		assert_equal({0=>0, 1=>1, 2=>2}, @a.get_mib_entry('1.2.3').to_hash)
		assert_equal(0, @a.get_mib_entry('1.2.3.0'))
		assert_equal({0=>5, 1=>6, 2=>7}, @a.get_mib_entry('4.5.6').to_hash)
		assert_equal(6, @a.get_mib_entry('4.5.6.1'))
	end

	def test_plugins_must_be_leaf_nodes
		# OK, since the tree is empty
		assert_nothing_raised { @a.add_plugin('1.2.3') { 42 } }
		
		# OK, since it's in a separate top-level branch
		assert_nothing_raised { @a.add_plugin('2.3.4') { [5, 6, 7] } }
		
		# OK, since it's coming off an adjacent node
		assert_nothing_raised { @a.add_plugin('2.3.5') { [8, 13, 21] } }
		
		# Not OK, since we'd overwrite an existing subtree
		assert_raise(ArgumentError) { @a.add_plugin('1') { "muahahahaha!" } }

		# Not OK, since it would attach itself somewhere inside an
		# existing plugin's "namespace"
		assert_raise(ArgumentError) { @a.add_plugin('1.2.3.4') { "help me!" } }
		
		# Now try to add a proxy instead
		assert_raise(ArgumentError) { @a.add_proxy('1', 'localhost', 16161) }
		assert_raise(ArgumentError) { @a.add_proxy('1.2.3.4', 'localhost', 16161) }
		
		# And what about if we try to add plugins over an existing proxy?
		assert_nothing_raised { @a.add_proxy('1.3.5', 'localhost', 16161) }
		
		assert_raise(ArgumentError) { @a.add_plugin('1.3.5.7') { 'feh' } }
	end

	def test_a_tree_of_data
		@a.add_plugin('1.2.3') { [[11, 12, 13], [21, 22, 23], [31, 32, 33]] }

		assert_equal({0=>{0=>11, 1=>12, 2=>13}, 1=>{0=>21, 1=>22, 2=>23}, 2=>{0=>31, 1=>32, 2=>33}},
		             @a.get_mib_entry('1.2.3').to_hash)
		assert_equal(SNMP::NoSuchObject, @a.get_snmp_value('1.2.3'))
		assert_equal({0=>11, 1=>12, 2=>13}, @a.get_mib_entry('1.2.3.0').to_hash)
		assert_equal(SNMP::NoSuchObject, @a.get_snmp_value('1.2.3.0'))
		
		3.times { |i|
			3.times { |j|
				assert_equal("#{i+1}#{j+1}".to_i, @a.get_mib_entry("1.2.3.#{i}.#{j}"))
			}
		}
	end

	def test_a_bridge_too_far
		@a.add_plugin('1.2.3') { [0, 1, 2] }
		
		# Fails because we don't have .1.2.3.4
		assert_equal(nil, @a.get_mib_entry('1.2.3.4'))
		assert_equal(SNMP::NoSuchObject, @a.get_snmp_value('1.2.3.4'))
		
		# Fails because we don't have a subtree from .1.2.3.1
		assert_equal(nil, @a.get_mib_entry('1.2.3.1.0'))
		assert_equal(SNMP::NoSuchObject, @a.get_snmp_value('1.2.3.1.0'))
	end

	def test_next_oid_in_tree
		@a.add_plugin('1.1') { [nil, %w{the quick brown etc}] }
		@a.add_plugin('1.2.3') { [0, 1, 2] }
		@a.add_plugin('4.5.6') { [5, 6, 7] }

		# Simple case -- delve into the tree in the same plugin
		assert_equal('1.2.3.0', @a.next_oid_in_tree('1.2.3').to_s)
		
		# Simple edge case -- last element within the same plugin
		assert_equal('1.2.3.2', @a.next_oid_in_tree('1.2.3.1').to_s)

		# Slightly harder -- find the first real value in the next tree
		assert_equal('1.2.3.0', @a.next_oid_in_tree('1.2').to_s)
		
		# Find when between jobs
		assert_equal('4.5.6.0', @a.next_oid_in_tree('2.3.4.5.6.78').to_s)
		
		# What about when we're off the end of the tree?
		assert_equal(SNMP::EndOfMibView, @a.next_oid_in_tree('5'))
		
		# Or even *at* the end of the tree
		assert_equal(SNMP::EndOfMibView, @a.next_oid_in_tree('4.5.6.2'))

	end

	def test_dir_of_plugins
		tmpdir = File.join(Dir::tmpdir, "rubysnmp.#{$$}")
		Dir.mkdir(tmpdir)
		
		File.open(tmpdir + '/3.2.1', 'w') {|fd|
			fd.puts "42"
		}
		
		File.open(tmpdir + '/4', 'w') {|fd|
			fd.puts "[[Time.now.to_i]]"
		}

		File.open(tmpdir + '/README', 'w') {|fd|
			fd.puts "This directory is full of SNMP plugins, but this file won't be read."
		}
		
		File.open(tmpdir + '/6.6.6', 'w') {|fd|
			fd.puts "Not valid ruby code.  That's OK though, we should just be able to ignore it."
		}

		@a.add_plugin_dir(tmpdir)
		FileUtils.rm_rf(tmpdir)
		
		assert_equal(42, @a.get_mib_entry('3.2.1'))
		assert_equal(nil, @a.get_mib_entry('3.2.1.0'))
		assert((Time.now.to_i - @a.get_mib_entry('4.0.0')).abs < 2)
	end

	def test_rb_plugin_files
		tmpdir = File.join(Dir::tmpdir, "rubysnmp.#{$$}")
		Dir.mkdir(tmpdir)
		
		File.open(tmpdir + '/foo.rb', 'w') {|fd|
			fd.puts "self.add_plugin('3.2.1') { 42 }"
		}
		
		@a.add_plugin_dir(tmpdir)
		FileUtils.rm_rf(tmpdir)
		
		assert_equal(42, @a.get_mib_entry('3.2.1'))
		assert_equal(nil, @a.get_mib_entry('3.2.1.0'))
	end
	
	def test_empty_plugin_return
		@a.add_plugin('1.2.3.4') { {} }
		@a.add_plugin('4.3.2.1') { [] }
		@a.add_plugin('2.3.4') { {0 => [1, 2, 3], 1 => [] } }
		
		assert_equal(SNMP::NoSuchObject, @a.get_snmp_value('1.2.3.4'))
		assert_equal(SNMP::NoSuchObject, @a.get_snmp_value('4.3.2.1'))
		assert_equal(SNMP::NoSuchObject, @a.get_snmp_value('2.3.4.1'))
		assert_equal(SNMP::EndOfMibView, @a.next_oid_in_tree('2.3.4.0.2'))
	end

	def test_exception_throwing_plugin
		@a.add_plugin('1.2.3') { raise "Broooooken!" }
		@a.add_plugin('3.2.1') { raise "Still broooooken!" }
		
		assert_equal(nil, @a.get_mib_entry('1.2.3.4'))
		assert_equal(SNMP::NoSuchObject, @a.get_snmp_value('1.2.3.4'))
		assert_equal(SNMP::EndOfMibView, @a.next_oid_in_tree('3.2.1.0'))
	end

	def test_next_oid_from_multiple_array_plugins
		@a.add_plugin('1.2.3.1') { [ 1 ] }
		@a.add_plugin('1.2.3.2') { [ 2 ] }
		@a.add_plugin('1.2.3.3') { [ 3 ] }
		
		assert_equal(2, @a.get_snmp_value('1.2.3.2.0'))
		assert_equal('1.2.3.3.0', @a.next_oid_in_tree('1.2.3.2.0').to_s)
	end
	
	def test_next_oid_into_single_value_plugins
		@a.add_plugin('1.2.3.1') { [ 1 ] }
		@a.add_plugin('1.2.3.2') { 2 }
	
		assert_equal('1.2.3.2', @a.next_oid_in_tree('1.2.3.1.0').to_s)
	end

	def test_return_other_snmp_types
		@a.add_plugin('1.2.3') { [ SNMP::IpAddress.new('127.0.0.1') ] }
		
		v = @a.get_snmp_value('1.2.3.0')
		assert_equal(SNMP::IpAddress, v.class)
		assert_equal('127.0.0.1', v.to_s)
	end
end
