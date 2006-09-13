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
# do much of anything -- it isn't capable of returning meaningful results. 
# In order to get data out of it, you'll need to define code to examine the
# host machine and it's environment and return data.
#
# What values get returned is determined by "plugins", small chunks of code
# that return values that the agent can then send back to the requestor.
#
# This agent currently only supports Get requests, but GetNext is high on
# the priority list (so that we can support walks).
#
# = Simple example agent
#
#    require 'snmp/agent'
#
#    agent = SNMP::Agent.new(:port => 16161, :logger => Logger.new(STDOUT))
#    agent.add_plugin('1.3.6.1.2.1.1.5.0') { 'hostname.example.com' }
#    agent.start()
#
# This agent will respond to requests for the given OID (sysName, as it happens)
# and return the octet string 'hostname.example.com' to that request.  Any other
# request will be given a 'No such object' response.
#
# = Writing plugins
#
# I've tried to make writing plugins as painless as possible, but unfortunately
# there's still a fair amount of hassle that's required in some circumstances.
# A basic understanding of how SNMP MIBs and OIDs work will probably help
# somewhat.
#
# The basic layout of all plugins is the same -- you map a base OID to a
# chunk of code, and then any requests for that subtree cause the code to be
# executed.  You use +SNMP::Agent#add_plugin+ method to add a new plugin.
# This method takes a base OID (as a string or an array of integers) and a
# block of code to be run when the requested OID matches the given base OID.
#
# The result from the block of code should either be a single value
# (if you want the base OID to return a value itself), a simple array (if
# the base OID maps to a list of entries), or a tree of arrays that describes
# the data underneath the base OID.
#
# For example, if you want OID .1.2.3 to return the single value 42, you would
# do something like this:
#
#    agent = SNMP::Agent.new
#    agent.add_plugin('1.2.3') { 42 }
#
# Internally, when a Get request for the OID .1.2.3 is received, the agent
# will find the plugin, run it, and return a PDU containing 'INTEGER: 42'.
# Any request for an OID below .1.2.3 will be answered with NoSuchObject
# (unless there's another plugin that handles some subtree of .1.2.3).
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
# At present, it is not possible to produce a "sparse" list (eg a process list,
# like hrSWRunName), though that is a planned feature.
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

class Agent
	DefaultSettings = { :listen_port => 161,
							  :max_packet => 8000,
							  :logger => Logger.new('/dev/null')
							}

	def initialize(settings = {})
		settings = DefaultSettings.merge(settings)
		
		@port = settings[:listen_port]
		@log = settings[:logger]
		@max_packet = settings[:max_packet]
		
		@mib_tree = {}
	end

	def add_plugin(base_oid, &block)
		base_oid = ObjectId.new(base_oid) unless base_oid.is_a? ObjectId

		current_node = @mib_tree
		(base_oid.length - 1).times do |oid_idx|
			next_step = base_oid[oid_idx]
			throw ArgumentError.new("#{next_step.inspect} is not an integer") unless next_step.is_a? ::Integer
			if current_node[next_step].nil?
				current_node[next_step] = {}
			end
			if current_node[next_step].is_a? Proc
				raise ArgumentError.new("Adding plugin #{base_oid} would encroach on the subtree of an existing plugin")
			end
			current_node = current_node[next_step]
		end

		unless current_node[base_oid[-1]].nil?
			raise ArgumentError.new("OID #{base_oid} is already occupied by something; cannot put a plugin here")
		end
		current_node[base_oid[-1]] = block
	end

	def start
		@socket = UDPSocket.open
		@socket.bind(nil, listen_port)

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
						response = self.process_get_request(message)
					when GetNextRequest
						@log.debug "GetNextRequest received"
						response = message.response
						response.pdu.varbind_list.each do |v|
							@log.debug "OID: #{v.name}"
							if v.name.to_s == '1.3.6.1.2.1'
								v.name = SNMP::ObjectId.new('1.3.6.1.2.1.1')
							else
								v.name[-1] += 1 unless v.name[-1] > 10
							end
							v.value = SNMP::Integer.new(v.name[-1])
							@log.debug "The next OID on platform 1 is #{v.name}"
						end
					when SetRequest
						response = message.response
					else
						raise "invalid message #{message.inspect}"
				end
				encoded_message = response.encode
				n=@socket.send(encoded_message, 0, remote_info[3], remote_info[1])
				@log.debug encoded_message.inspect
			rescue => e
				@log.error e
				shutdown
			end
		end
	end
	
	def shutdown
		@log.info "SNMP agent stopping"
		@socket.close
		exit
	end

	alias stop :shutdown

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
		response.pdu.varbind_list.each do |v|
			@log.debug "OID: #{v.name}"
			v.name = self.next_oid_in_tree(v.name)
			v.value = get_snmp_value(v.name)
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
		elsif data_value.nil? or data_value.is_a? Array or data_value.is_a? Hash
			SNMP::NoSuchObject.new
		else
			SNMP::OctetString.new(data_value.to_s)
		end
	end
	
	def get_mib_entry(oid)
		@log.debug "Looking for MIB entry #{oid.to_s}"
		oid = ObjectId.new(oid)
		current_node = @mib_tree
		
		while oid.length > 0
			here = oid.shift
			@log.debug "Now going to #{here}"
			# If we're going to walk a tree entry, it'll want
			# to be something we can walk into
			unless current_node.is_a? Array or current_node.is_a? Hash or current_node.is_a? Proc
				@log.debug "Current node isn't something I know how to deal with; bailing"
				return nil
			end
			current_node = current_node[here]
			current_node = current_node.call if current_node.is_a? Proc
			if current_node.nil?
				@log.debug "Current node is nil; nothing good can come of this"
				return nil
			end
		end
		
		current_node
	end

	def next_oid_in_tree(oid)
		@log.debug "Looking for the next OID from #{oid.to_s}"
		oid = ObjectId.new(oid) unless oid.is_a? ObjectId
		
		next_oid = []
		
		current_node = get_mib_entry(oid)
		current_node = current_node.call if current_node.is_a? Proc
		
		@log.debug "Current node is a(n) #{current_node.class}"
		if current_node.is_a? Array or current_node.is_a? Hash
			@log.debug "There is a subtree from #{oid.to_s}"
			# There is a subtree below the requested location, so we just need
			# to walk down the far "left" (lowest numbered entry) of the tree
			# until we hit the end, and that's our next.
			next_oid = oid.dup
			while current_node.is_a? Array or current_node.is_a? Hash or current_node.is_a? Proc
				current_node = current_node.call if current_node.is_a? Proc
				next_oid << current_node.keys.sort[0]
				current_node = current_node[next_oid[-1]]
			end
			
			@log.debug "Next OID from #{oid.to_s} is #{next_oid.to_s}"
			return next_oid
		end
		
		# Bugger, the OID given to the GetNext is either a leaf node or
		# doesn't exist at all.  This means that we need to tromp through the
		# given OID, slowly and carefully, making sure to only add to the
		# next_oid when the current node has a larger neighbour.  Then once
		# we've worked out what the start of the "next" is, we walk it's left
		# side to find the endpoint.  Blergh.
		current_node = @mib_tree
		@log.debug "Walking the entire tree"
		oid.length.times do |oid_idx|
			@log.debug "Level #{oid_idx} in the tree"
			@log.debug "Node in our OID is #{oid[oid_idx]}"
			current_node = current_node.call if current_node.is_a? Proc
			
			# Are we at a dead-end in the tree?
			break if current_node.nil?
			maybe_next = current_node.keys.sort.find {|v| v > oid[oid_idx]}
			@log.debug "Next element in the tree at this level is #{maybe_next}"
			
			# The 'next' OID is constructed of the path through the tree that got
			# us to this node, plus the node 'next' to this one at this level of the
			# tree.  If there's no 'next' node at this level, then we shouldn't update
			# the next_oid because at the moment the 'next' OID is in a whole separate
			# subtree
			if oid_idx == 0
				path_to_here = []
			else
				path_to_here = oid[0, oid_idx - 1]
			end
			next_oid = ObjectId.new(path_to_here + [maybe_next]) unless maybe_next.nil?
			@log.debug "I currently think the next OID is somewhere below #{next_oid.to_s}"
			current_node = current_node[oid[oid_idx]]
		end

		# Special case: if our next_oid is empty, then we've ended up off the end of the
		# MIB and it's time to send back an error
		if next_oid.length == 0
			return SNMP::EndOfMibView.new
		end

		# So, we start from where we left off above, and then walk through that subtree
		# to find the *real* first entry
		current_node = get_mib_entry(next_oid)
		while current_node.is_a? Array or current_node.is_a? Hash or current_node.is_a? Proc
			@log.debug "Now at #{next_oid.to_s}"
			current_node = current_node.call if current_node.is_a? Proc
			@log.debug "Keys at this level are #{current_node.keys.inspect}"
			@log.debug "First node at this level is #{current_node.keys.sort[0]}"
			next_oid << current_node.keys.sort[0]
			current_node = current_node[next_oid[-1]]
		end

		ObjectId.new(next_oid)
	end
end

end

class Array
	def keys
		k = []
		self.length.times { |v| k << v }
		k
	end
end


if $0 == __FILE__
agent = SNMP::Agent.new(1061)
trap("INT") { agent.shutdown }
agent.start
end
