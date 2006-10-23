#!/usr/bin/ruby
#
# Portions Copyright (c) 2004 David R. Halliday
# All rights reserved.
#
# This SNMP library is free software.  Redistribution is permitted under the
# same terms and conditions as the standard Ruby distribution.  See the
# COPYING file in the Ruby distribution for details.
#
# Portions Copyright (c) 2006 Matthew Palmer <mpalmer@hezmatt.org>
# All rights reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation (version 2 of the License)
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston MA  02110-1301 USA
#

require 'snmp'
require 'socket'
require 'logger'

module SNMP

##
# == SNMP Agent skeleton.
#
# Objects of this class are capable of acting as SNMP agents -- that is,
# receiving SNMP PDUs and (possibly) returning data as a result of those
# requests.
#
# We call this class a skeleton, though, since as it stands this agent won't
# do much of anything -- it only has support for the most basic of system
# information (sysDescr, sysUptime, sysContact, sysName, and sysLocation).
# In order to get more interesting data out of it, you'll need to define
# code to examine the host machine and it's environment and return data.
#
# What values get returned is determined by "plugins", small chunks of code
# that return values that the agent can then send back to the requestor.
#
# = Simple example agent
#
#    require 'snmp/agent'
#
#    agent = SNMP::Agent.new(:port => 16161, :logger => Logger.new(STDOUT))
#    agent.add_plugin('1.3.6.1.2.1.25.1.1.0') do
#      SNMP::TimeTicks.new(File.read('/proc/uptime').split(' ')[0].to_f * 100).to_i)
#    end
#    agent.start()
#
# This agent will respond to requests for the given OID (hrSystemUptime in
# this case, as it happens) and return the number of time ticks as read from
# the /proc/uptime file.  In this plugin, we've defined the exact and
# complete OID that we want to return the value of, but that's by no means
# necessary -- one plugin can handle a larger number of OIDs in itself by
# simply defining the 'base' OID it wants to handle, and returning
# structured data when it's called.  The pre-defined plugin for basic system
# parameters is a good (if basic) example of how you structure your data.
#
# = Writing plugins
#
# I've tried to make writing plugins as painless as possible, but
# unfortunately there's still a fair amount of hassle that's required in
# some circumstances. A basic understanding of how SNMP MIBs and OIDs work
# will help immensely.
#
# The basic layout of all plugins is the same -- you map a base OID to a
# chunk of code, and then any requests for that subtree cause the code to be
# executed.  You use +SNMP::Agent#add_plugin+ method to add a new plugin.
# This method takes a base OID (as a string or an array of integers) and a
# block of code to be run when the requested OID matches the given base OID.
#
# The result from the block of code should either be a single value (if you
# want the base OID to return a value itself), a simple array or hash (if
# the base OID maps to a list of entries), or a tree of arrays and hashes
# that describes the data underneath the base OID.
#
# For example, if you want OID .1.2.3 to return the single value 42, you
# would do something like this:
#
#    agent = SNMP::Agent.new
#    agent.add_plugin('1.2.3') { 42 }
#
# Internally, when a Get request for the OID .1.2.3 is received, the agent
# will find the plugin, run it, and return a PDU containing 'INTEGER: 42'.
# Any request for an OID below .1.2.3 will be answered with NoSuchObject.
#
# On the topic of plugins and subtrees: you cannot have a plugin respond
# to a subtree of another plugin.  That is, if you have one plugin which
# has registered itself as handling '1.2.3', you cannot have another plugin
# that says it handles '1.2' or '1.2.3.4' -- in either case, the two plugins
# will conflict.  Whether this behaviour is fixed in the future depends on
# whether it turns out to be a limitation that causes major hassle.
#
# There is a limted amount of type interpolation in the plugin running code.
# At present, integer values will be kept as integers, and most everything
# else will be converted to an OCTET STRING.  If you have a particular need
# to return values of particular SNMP types, the agent will pass-through any
# SNMP value objects that are created, so if you just *had* to return a
# Gauge32 for a particular OID, you could do:
#
#    agent.add_plugin('1.2.3') { SNMP::Gauge32.new(42) }
#
# Getting more complex, if you wanted OID .1.2.3 to return a list of values,
# you can return an array:
#
#    agent.add_plugin('1.2.3') { %{the quick brown fox jumped over the lazy dog} }
#
# That will get you OIDs .1.2.3.0 through .1.2.3.8 containing a word each from
# the ever-famous typing test.
#
# To produce deeper trees of data within a single plugin, you can have
# arrays within arrays, like this:
#
#    agent.add_plugin('1.2.3') { [[0, 1, 2], [10, 11, 12], [20, 21, 22]])
#
# This will return the following values for the following OIDs:
#
#    .1.2.3.0.0 => 0
#    .1.2.3.0.1 => 1
#    .1.2.3.0.2 => 2
#    .1.2.3.1.0 => 10
#    .1.2.3.1.1 => 11
#    .1.2.3.1.2 => 12
#    .1.2.3.2.0 => 20
#    .1.2.3.2.1 => 21
#    .1.2.3.2.2 => 22
#
# The agent walks through the array, using elements of the OID to dereference
# each level of the array, before finally arriving at a value.  If the OID
# runs out before getting to a scalar value, or the arrays run out while there's
# will elements of the OID, then NoSuchObject is returned.
#
# You can produce "sparse" lists of values (such as required by the hrRun table)
# by using a hash and giving the values for each OID as values to integer keys.
# If you try to use non-integer keys in your hash things will explode, however.
#
# = Caching plugin data
#
# Often, running a plugin to collect data is quite expensive -- if you're
# calling out to a web service or doing a lot of complex calculations, and
# generating a large resulting tree, you really don't want to be re-doing
# all that work for every SNMP request (and remember, during a walk, that
# tree is going to be completely recreated for every element walked in that
# tree).
#
# To prevent this problem, the SNMP agent provides a fairly simple caching
# mechanism within itself.  If you return the data from your plugin as a
# hash, you can add an extra element to that hash, with a key of +:cache+,
# which should have a value of how many seconds you want the agent to retain
# your data for before re-running the plugin.  So, a simple cached data tree
# might look like:
#
#   {:cache => 30, 0 => [0, 1, 2], 1 => ['a', 'b', 'c']}
#
# So the agent will cache the given data (+{0 => [...], 1 => [...]}+) for
# 30 seconds before running the plugin again to get a new set of data.
#
# How long should you cache data for?  That's up to you.  The tradeoffs are
# between the amount of time it takes to create the data tree, how quickly
# the data "goes stale", and how large the data tree is.  The longer it
# takes to re-create the tree and the larger the tree is, the longer you
# should cache for.  Large trees should be cached for longer because big
# trees take longer to walk, and it'd be annoying if, half-way through the
# walk, the plugin got called again.  How long the data is relevant for is
# essentially the upper bound on cache time -- there's no point in keeping
# data around for longer than it's valid.
#
# What if, for some reason, you can't come up with a reasonable cache
# timeout value? You've got a huge tree, that takes ages to produce, but it
# needs to be refreshed really often.  Try splitting your single monolithic
# plugin into smaller "chunks", each of which can be cached separately. The
# smaller trees will take less time to walk, and hopefully you won't need to
# do the full set of processing to obtain the subset of values, so it'll be
# quicker to process.
# 
# = Bulk plugin loading
#
# If you've got a large collection of plugins that you want to include in
# your system, you don't have to define them all by hand within your code --
# you can use the +add_plugin_dir+ method to load all of the plugins present
# in a directory.
#
# There are two sorts of plugin files recognised by the loader:
#
#  - Any files whose names look like OIDs.  In this case, the filename is
#    used as the base OID for the plugin, and the contents of the file are
#    taken as the complete code to run for the plugin.  This method is
#    really only suitable for fairly simple plugins, and is mildly
#    deprecated -- practical experience has shown that this method of
#    defining a plugin is actually fairly confusing.
#
#  - Any file in the plugin directory which ends in +.rb+ is evaluated as
#    ruby code, in the context of the SNMP::Agent object which is running
#    +add_plugin_dir+.  This means that any methods or classes defined in
#    the file are in the scope of the SNMP::Agent object itself.  To
#    actually add a plugin in this instance, you need to run
#    +self.add_plugin+ explicitly. This method of defining plugins
#    externally is preferred, since although it is more verbose, it is much
#    more flexible and lends itself to better modularity of plugins.
#
# = Proxying to other SNMP agents
#
# Although the Ruby SNMP agent is quite versatile, it currently lacks a lot
# of the standard MIB trees that we know and love.  This means, of course,
# that if you want to walk standard trees, like load averages, disk
# partitions, and network statistics, you'll need to be running another SNMP
# agent on your machines in addition to this agent.  Rather than doing the
# dirty and making you remember whatever non-standard port you may have put
# one (or both) of the agents on, you can instead proxy the other agent
# through the Ruby SNMP agent.
#
# The syntax for this is very simple:
#
#   agent.add_proxy(oid, host, port)
#
# This simple call will cause any request to any part of the MIB subtree
# rooted at <oid> to be fulfilled by making an SNMP request to the agent
# running on <host> and listening on <port> and returning whatever that
# agent sends back to us.
#
# A (minor) limitation at the moment is that you can't proxy a subtree
# provided by the backend agent to a different subtree in the Ruby SNMP
# agent.  I don't consider this to be a major limitation, as -- due to the
# globally-unique and globally-meaningful semantics of the MIB -- you
# shouldn't have too much call for changing OIDs in proxies.
#

class Agent
	DefaultSettings = { :port => 161,
	                    :max_packet => 8000,
	                    :logger => Logger.new('/dev/null'),
	                    :sysContact => "Someone",
	                    :sysName => "Ruby SNMP agent",
	                    :sysLocation => "Unknown"
	                  }

	# Create a new agent.
	#
	# You can provide a list of settings to the new agent, as a hash of
	# symbols and values.  Currently valid settings (and their defaults)
	# are as follows:
	#
	#   :port -- The UDP port to listen on.  Default: 161
	#   :max_packet -- The largest UDP packet that will be read.  Default: 8000
	#   :logger -- A Logger object to write all messages to.  Default: sends all
	#             messages to /dev/null.
	#   :sysContact -- A string to provide when an SNMP request is made for
	#             sysContact.  Default: "Someone"
	#   :sysName -- A string to provide when an SNMP request is made for
	#             sysName.  Default: "Ruby SNMP agent"
	#   :sysLocation -- A string to provide when an SNMP request is made for
	#             sysLocation.  Default: "Unknown"
	#
	def initialize(settings = {})
		settings = DefaultSettings.merge(settings)
		
		@port = settings[:port]
		@log = settings[:logger]
		@max_packet = settings[:max_packet]
		
		@mib_tree = MibNode.new(:logger => @log)
		
		agent_start_time = Time.now
		self.add_plugin('1.3.6.1.2.1.1') { {1 => [`uname -a`],
		                                    3 => [SNMP::TimeTicks.new(((Time.now - agent_start_time) * 100).to_i)],
		                                    4 => ["Someone"],
		                                    5 => ["RubySNMP Agent"],
		                                    6 => ["Unknown"]
		                                   }
		                                 }
	end

	# Handle a new OID.
	#
	# See the class documentation for full information on how to use this method.
	#
	def add_plugin(base_oid, &block)
 		raise ArgumentError.new("Must pass a block to add_plugin") unless block_given?
		@mib_tree.add_node(base_oid, MibNodePlugin.new(:logger => @log, &block))
	end

	# Add a directory full of plugins to the agent.
	#
	# To make it as simple as possible to provide plugins to the SNMP agent,
	# you can create a directory and fill it with files containing plugin
	# code, then tell the agent where to find all that juicy code.
	#
	# The files in the plugin directory are simply named after the base OID,
	# and the contents are the code you want to execute, exactly as you would
	# put it inside a block.
	#
	def add_plugin_dir(dir)
		orig_verbose = $VERBOSE
		$VERBOSE = nil
		Dir.entries(dir).each do |f|
			@log.info("Looking at potential plugin #{File.join(dir, f)}")
			if f =~ /^([0-9]\.?)+$/
				begin
					self.add_plugin(f, &eval("lambda do\n#{File.read(File.join(dir, f))}\nend\n"))
				rescue SyntaxError => e
					@log.warn "Syntax error in #{File.join(dir, f)}: #{e.message}"
				end
			elsif f =~ /\.rb$/
				begin
					self.instance_eval(File.read(File.join(dir, f)))
				rescue SyntaxError => e
					@log.warn "Syntax error in #{File.join(dir, f)}: #{e.message}"
				end
			end
		end
			
		$VERBOSE = orig_verbose
	end

	def add_proxy(base_oid, host, port)
		@mib_tree.add_node(base_oid, SNMP::MibNodeProxy.new(base_oid, host, port))
	end

	# Main connection handling loop.
	#
	# Call this method when you're ready to respond to some SNMP messages.
	#
	# Caution: this method blocks (does not return until it's finished
	# serving SNMP requests).  As a result, you should run it in a separate
	# thread or catch one or more signals so that you can actually call
	# +shutdown+ to stop the agent.
	def start
		@socket = UDPSocket.open
		@socket.bind('', @port)

		@log.info "SNMP agent running"
		loop do
			begin
				data, remote_info = @socket.recvfrom(@max_packet)
				@log.debug "Received #{data.length} bytes"
				@log.debug data.inspect
				@log.debug "Responding to #{remote_info[3]}:#{remote_info[1]}"
				message = Message.decode(data)
				case message.pdu
					when GetRequest
						@log.debug "GetRequest received"
						response = process_get_request(message)
					when GetNextRequest
						@log.debug "GetNextRequest received"
						response = process_get_next_request(message)
					else
						raise SNMP::UnknownMessageError.new("invalid message #{message.inspect}")
				end
				encoded_message = response.encode
				n=@socket.send(encoded_message, 0, remote_info[3], remote_info[1])
				@log.debug encoded_message.inspect
			rescue SNMP::UnknownMessageError => e
				@log.error "Unknown SNMP message: #{e.message}"
			rescue IOError => e
				break if e.message == 'stream closed' or e.message == 'closed stream'
				@log.warn "IO Error: #{e.message}"
			rescue => e
				@log.error "Error in handling message: #{e.message}"
			end
		end
	end

	# Stop the running agent.
	#
	# Close the socket and stop the agent from running.  It can be started again
	# just by calling +start+ again.  You will, of course, need to be catching
	# signals or be multi-threaded in order to be able to actually call this
	# method, because +start+ itself is a blocking method.
	#
	def shutdown
		@log.info "SNMP agent stopping"
		@socket.close
	end

	private
	def process_get_request(message)
		response = message.response
		response.pdu.varbind_list.each do |v|
			@log.debug "GetRequest OID: #{v.name}"
			v.value = get_snmp_value(v.name)
		end

		response
	end

	def process_get_next_request(message)
		response = message.response
		response.pdu.varbind_list.length.times do |idx|
			v = response.pdu.varbind_list[idx]
			@log.debug "OID: #{v.name}"
			v.name = next_oid_in_tree(v.name)
			@log.debug "pgnr: Next OID is #{v.name.to_s}"
			if SNMP::EndOfMibView == v.name
				@log.debug "Setting error status"
				v.name = ObjectId.new('0')
				response.pdu.error_status = :noSuchName
				response.pdu.error_index = idx
			else
				@log.debug "Regular value"
				v.value = get_snmp_value(v.name)
			end
		end
	
		response
	end
	
	def get_snmp_value(oid)
		@log.debug("get_snmp_value(#{oid.to_s})")
		data_value = get_mib_entry(oid)
		
		if data_value.is_a? ::Integer
			SNMP::Integer.new(data_value)
		elsif data_value.is_a? String
			SNMP::OctetString.new(data_value)
		elsif data_value.nil? or data_value.is_a? MibNode
			SNMP::NoSuchObject
		elsif data_value.is_a? SNMP::Integer
			data_value
		else
			SNMP::OctetString.new(data_value.to_s)
		end
	end
	
	def get_mib_entry(oid)
		@log.debug "Looking for MIB entry #{oid.to_s}"
		oid = ObjectId.new(oid)
		@mib_tree.get_node(oid)
	end

	def next_oid_in_tree(oid)
		@log.debug "Looking for the next OID from #{oid.to_s}"
		oid = ObjectId.new(oid) unless oid.is_a? ObjectId
		
		next_oid = @mib_tree.next_oid_in_tree(oid)
		
		if next_oid.nil?
			next_oid = SNMP::EndOfMibView
		end
		
		next_oid
	end
		
end

class MibNode
	def initialize(initial_data = {})
		@log = initial_data.keys.include?(:logger) ? initial_data.delete(:logger) : Logger.new('/dev/null')
		@subnodes = {}

		initial_data.keys.each do |k|
			raise ArgumentError.new("MIB key #{k} is not an integer") unless k.is_a? ::Integer
			@subnodes[k] = initial_data[k]
			if @subnodes[k].is_a? Array or @subnodes[k].is_a? Hash
				@subnodes[k] = MibNode.new(@subnodes[k].to_hash.merge(:logger => @log))
			end
		end
	end

	def keys
		subnodes.keys
	end
	
	def length
		subnodes.length
	end

	def to_hash
		output = {}
		self.keys.each do |k|
			output[k] = subnodes[k].respond_to?(:to_hash) ? subnodes[k].to_hash : subnodes[k]
		end
		
		output
	end
	
	def get_node(oid)
		oid = ObjectId.new(oid)

		next_idx = oid.shift
		if next_idx.nil?
			# End of the road, bud
			return self
		end

		next_node = sub_node(next_idx)
		if next_node.is_a? MibNode
			# Walk the line
			return next_node.get_node(oid)
		elsif oid.length == 0
			# Got to the end of the OID at just the right time
			return next_node
		else
			# We're out of tree but not out of path... so it must be nil!
			return nil
		end
	end
	
	def add_node(oid, node)
		oid = ObjectId.new(oid) unless oid.is_a? ObjectId

		if oid.length == 1
			if subnodes[oid[0]].nil?
				subnodes[oid[0]] = node
			else
				raise ArgumentError.new("OID #{oid} is already occupied by something; cannot put a plugin here")
			end
		else
			sub = oid.shift
			if subnodes[sub].nil?
				subnodes[sub] = SNMP::MibNode.new(:logger => @log)
			end
			
			if subnodes[sub].is_a? SNMP::MibNodePlugin
				raise ArgumentError.new("Adding plugin #{oid} would encroach on the subtree of an existing plugin")
			else
				subnodes[sub].add_node(oid, node)
			end
		end
	end

	# Return the path down the 'left' side of the MIB tree from this point.
	# The 'left' is, of course, the smallest node in each subtree until we
	# get to a leaf.
	def left_path()
		next_idx = self.keys.sort[0]

		# Dereference into the subtree. Let's see what we've got here, shall we?
		next_node = sub_node(next_idx)
		
		if next_node.is_a? MibNode
			# Walk the line
			path = next_node.left_path()
		else
			path = []
		end

		# Add ourselves to the front of the path
		path.unshift(next_idx)

		return path
	end

	def next_oid_in_tree(oid)
		@log.debug("MibNode#next_oid_in_tree(#{oid})")
		oid = ObjectId.new(oid)

		# End of the line, bub
		return self.left_path if oid.length == 0

		sub = oid.shift

		next_oid = if subnodes[sub].respond_to? :next_oid_in_tree
			@log.debug("subnode #{sub} (of class #{subnodes[sub].class}) talks next_oid_in_tree")
			subnodes[sub].next_oid_in_tree(oid)
		end
		
		@log.debug("Got #{next_oid} from call to subnodes[#{sub}].next_oid_in_tree(#{oid})")
		
		if next_oid.nil?
			@log.debug("No luck asking subtree #{sub}; how about the next subtree?")
			sub = subnodes.keys.sort.find { |k| k > sub }
			next_oid = if subnodes[sub].respond_to? :left_path
				@log.debug("Looking at the left path of subtree #{sub}")
				subnodes[sub].left_path
			end
		end
		
		if next_oid.nil? and sub
			@log.debug("We've got no next subtree, just a lonely little node")
			next_oid = []
		end
		
		if next_oid.nil?
			@log.debug("This node has no valid next nodes")
			return nil
		else
			@log.debug("The next OID for #{oid} is #{next_oid.to_s}")
			return ObjectId.new(next_oid.unshift(sub))
		end
	end

	private
	def sub_node(idx)
		raise ArgumentError.new("Index [#{idx}] must be an integer in a MIB tree") unless idx.is_a? ::Integer
		
		# Dereference into the subtree. Let's see what we've got here, shall we?
		next_node = @subnodes[idx]
		
		if next_node.is_a? MibNodePlugin
			next_node = next_node.plugin_value
			if next_node.is_a? Array or next_node.is_a? Hash
				next_node = MibNode.new(next_node.to_hash.merge(:logger => @log))
			end
		end

		return next_node
	end

	def subnodes
		@subnodes
	end
end

class MibNodePlugin
	def initialize(opts = {}, &block)
		@log = opts[:logger].nil? ? Logger.new('/dev/null') : opts[:logger]
		@proc = block
		@cached_value = nil
		@cache_until = 0
	end
	
	def plugin_value
		if Time.now.to_i > @cache_until
			begin
				@cached_value = @proc.call
			rescue => e
				@log.warn("Plugin threw an exception: #{e.message}\n#{e.backtrace}")
				@cached_value = nil
			end
			if @cached_value.is_a? Hash
				unless @cached_value[:cache].nil?
					@cache_until = Time.now.to_i + @cached_value[:cache]
					@cached_value.delete :cache
				end
			end
		end
		
		@cached_value
	end
	
	def next_oid_in_tree(oid)
		data = self.plugin_value
		if data.is_a? Array
			data = data.to_hash
		end
		if data.is_a? Hash
			data = MibNode.new(data.merge({:logger => @log}))
		end
		
		data.next_oid_in_tree(oid)
	end
end

class MibNodeProxy < MibNode
	def initialize(base_oid, host, port)
		@base_oid = SNMP::ObjectId.new(base_oid)
		@manager = SNMP::Manager.new(:Host => host, :Port => port)
	end
	
	def get_node(oid)
		oid = SNMP::ObjectId.new(oid) unless oid.is_a? SNMP::ObjectId
		
		complete_oid = ObjectId.new(@base_oid + oid)
		
		rv = @manager.get([complete_oid])
		
		rv.varbind_list[0].value
	end
	
	# Cannot add a node inside a proxy
	def add_node(oid, node)
		raise ArgumentError.new("Cannot add a node inside a MibNodeProxy")
	end

	private
	def sub_node(x)
		raise RuntimeError.new("This method should never be called")
	end
end
			
# Raised when we have asked MibNode#get_node to get a node but have
# told it not to traverse plugins.
class TraversesPluginError < StandardError
end

# To signal that the agent received a message that it didn't know how to
# handle.
class UnknownMessageError < StandardError
end

end

class Array
	def keys
		k = []
		self.length.times { |v| k << v }
		k
	end
	
	def to_hash
		h = {}
		self.keys.each {|k| h[k] = self[k]}
		h
	end
end

class FalseClass
	def false?; true; end
	def true?; false; end
end

class TrueClass
	def false?; false; end
	def true?; true; end
end

if $0 == __FILE__
agent = SNMP::Agent.new(:port => 1061, :logger => Logger.new(STDOUT))
trap("INT") { agent.shutdown }
agent.start
end
