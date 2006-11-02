require File.dirname(__FILE__) + '/test_helper.rb'

require 'snmp/agent'

class ProxyTest < Test::Unit::TestCase
	def with_fake_remote
		SNMP::Manager::DefaultConfig[:Transport] = ICBINASnmpAgent
		rv = yield
		SNMP::Manager::DefaultConfig[:Transport] = SNMP::UDPTransport
		rv
	end
		
	def test_adding_a_proxy
		a = SNMP::Agent.new
		class << a
			public :get_mib_entry
		end
		
		a.add_proxy('1.3.6.1.4.1.2021', 'localhost', 16161)
		proxy_parent = a.get_mib_entry('1.3.6.1.4.1')
		assert_equal 1, proxy_parent.length
		assert_equal [2021], proxy_parent.keys
		proxy = proxy_parent.instance_eval("@subnodes[2021]")
		assert_equal SNMP::MibNodeProxy, proxy.class
		
		proxy_socket = proxy.instance_eval('@manager')
		assert_equal SNMP::Manager, proxy_socket.class
	end

	def test_getting_through_a_proxy
		p = with_fake_remote do
			SNMP::MibNodeProxy.new(:base_oid => '1.3.6.1.4.1.2021',
			                       :host => 'localhost',
			                       :port => 16161)
		end
		mgr = p.instance_eval("@manager")
		assert_equal SNMP::Manager, mgr.class
		
		# Pop open the manager so we can fiddle with it's mock transport
		class << mgr; attr_reader :transport; end
		assert_equal ICBINASnmpAgent, mgr.transport.class

		# Add a plugin to the 'remote' agent
		mgr.transport.agent.add_plugin('1.3.6.1.4.1.2021') { [[0, 1, 2], [10, 11, 12], [20, 21, 22]] }
		
		# Retrieve some data from the 'remote' through the proxy
		assert_equal 11, p.get_node('1.1')
		
		# Did the transport object get called correctly?
		assert_equal 'localhost', mgr.transport.host
		assert_equal 16161, mgr.transport.port

		# Examine the SNMP request that was sent
		req = SNMP::Message.decode(mgr.transport.last_packet)
		assert_equal SNMP::GetRequest, req.pdu.class
		assert_equal SNMP::VarBindList, req.pdu.varbind_list.class
		assert_equal 1, req.pdu.varbind_list.length
		assert_equal '1.3.6.1.4.1.2021.1.1', req.pdu.varbind_list[0].name.to_s
	end

	def test_get_through_proxy_infected_agent
		a = SNMP::Agent.new
		class << a
			public :process_get_request
		end

		with_fake_remote do
			a.add_proxy('1.3.6.1.4.1.2021', 'localhost', 16161)
		end

		# Extract out some interesting objects from the manager
		proxy_node = a.instance_eval("get_mib_entry('1.3.6.1.4.1')").instance_eval('@subnodes[2021]')
		assert_equal SNMP::MibNodeProxy, proxy_node.class
		assert_equal '1.3.6.1.4.1.2021', proxy_node.instance_eval("@base_oid").to_s
		transport = proxy_node.instance_eval('@manager').instance_eval('@transport')
		assert_equal ICBINASnmpAgent, transport.class
		
		# Add some data for the 'remote' agent to send to our proxy
		transport.agent.add_plugin('1.3.6.1.4.1.2021') { [[0, 1, 2], [10, 11, 12], [20, 21, 22]] }

		# Some local data, just for flavour
		a.add_plugin('1.2.3') { [0, 1, 2] }

		# First up, do we still get a regulation request/response from local data?
		msg = SNMP::Message.new(1, 'public', SNMP::GetRequest.new(1, SNMP::VarBindList.new('1.2.3.0')))
		resp = a.process_get_request(msg)
		
		assert_equal(SNMP::Message, resp.class)
		assert_equal(1, resp.pdu.varbind_list.length)
		assert_equal("INTEGER", resp.pdu.varbind_list[0].value.asn1_type)
		assert_equal(0, resp.pdu.varbind_list[0].value.to_i)
		
		# Does the proxy work directly?
		assert_equal 11, proxy_node.get_node('1.1')

		# Now, what about when we proxy?
		msg = SNMP::Message.new(1, 'public', SNMP::GetRequest.new(1, SNMP::VarBindList.new('1.3.6.1.4.1.2021.1.1')))
		resp = a.process_get_request(msg)

		# Did we proxy to the right place?
		assert_equal 'localhost', transport.host
		assert_equal 16161, transport.port

		# Examine the request that was made to the 'remote' agent
		req = SNMP::Message.decode(transport.last_packet)
		assert_equal SNMP::GetRequest, req.pdu.class
		assert_equal SNMP::VarBindList, req.pdu.varbind_list.class
		assert_equal 1, req.pdu.varbind_list.length
		assert_equal '1.3.6.1.4.1.2021.1.1', req.pdu.varbind_list[0].name.to_s
		
		# Now how about that response, huh?
		assert_equal(SNMP::Message, resp.class)
		assert_equal(1, resp.pdu.varbind_list.length)
		assert_equal("INTEGER", resp.pdu.varbind_list[0].value.asn1_type)
		assert_equal(11, resp.pdu.varbind_list[0].value.to_i)
	end

	def test_proxied_get_next
		p = with_fake_remote do
			SNMP::MibNodeProxy.new(:base_oid => '1.3.6.1.4.1.2021',
			                       :host => 'localhost',
			                       :port => 16161)
		end
		mgr = p.instance_eval("@manager")
		assert_equal SNMP::Manager, mgr.class
		
		# Pop open the manager so we can fiddle with it's mock transport
		class << mgr; attr_reader :transport; end
		assert_equal ICBINASnmpAgent, mgr.transport.class

		# Add a plugin to the 'remote' agent
		mgr.transport.agent.add_plugin('1.3.6.1.4.1.2021') { [[0, 1, 2], [10, 11, 12], [20, 21, 22]] }
		
		# Retrieve some data from the 'remote' through the proxy
		assert_equal '1.2', p.next_oid_in_tree('1.1').to_s
		
		# Did the transport object get called correctly?
		assert_equal 'localhost', mgr.transport.host
		assert_equal 16161, mgr.transport.port

		# Examine the SNMP request that was sent
		req = SNMP::Message.decode(mgr.transport.last_packet)
		assert_equal SNMP::GetNextRequest, req.pdu.class
		assert_equal SNMP::VarBindList, req.pdu.varbind_list.class
		assert_equal 1, req.pdu.varbind_list.length
		assert_equal '1.3.6.1.4.1.2021.1.1', req.pdu.varbind_list[0].name.to_s
	end
	
	def test_get_next_through_proxy_infected_agent
		a = SNMP::Agent.new
		class << a
			public :process_get_next_request
		end
		
		with_fake_remote do
			a.add_proxy('1.3.6.1.4.1.2021', 'localhost', 16161)
		end

		# Extract out some interesting objects from the manager
		proxy_node = a.instance_eval("get_mib_entry('1.3.6.1.4.1')").instance_eval('@subnodes[2021]')
		assert_equal SNMP::MibNodeProxy, proxy_node.class
		assert_equal '1.3.6.1.4.1.2021', proxy_node.instance_eval("@base_oid").to_s
		transport = proxy_node.instance_eval('@manager').instance_eval('@transport')
		assert_equal ICBINASnmpAgent, transport.class
		
		# Add some data for the 'remote' agent to send to our proxy
		transport.agent.add_plugin('1.3.6.1.4.1.2021') { [[0, 1, 2], [10, 11, 12], [20, 21, 22]] }

		# Some local data, just for flavour
		a.add_plugin('1.2.3') { [0, 1, 2] }

		# Now, what about when we proxy?
		msg = SNMP::Message.new(1, 'public', SNMP::GetNextRequest.new(1, SNMP::VarBindList.new('1.3.6.1.4.1.2021.1.1')))
		resp = a.process_get_next_request(msg)

		# Correct callee?
		assert_equal 'localhost', transport.host
		assert_equal 16161, transport.port

		# Now how about that response, huh?
		assert_equal(SNMP::Message, resp.class)
		assert_equal(1, resp.pdu.varbind_list.length)
		assert_equal('1.3.6.1.4.1.2021.1.2', resp.pdu.varbind_list[0].name.to_s)
		assert_equal("INTEGER", resp.pdu.varbind_list[0].value.asn1_type)
		assert_equal(12, resp.pdu.varbind_list[0].value.to_i)
	end
end

# I Can't Believe It's Not An SNMP Agent!
#
# What it actually is is a small sliver of a class that looks roughly like
# SNMP::UDPTransport, connected to an SNMP Agent -- just enough stuff to
# trick an SNMP Manager object into believing it's talking to an agent. The
# last SNMP packet received is retrievable through #last_packet.
#
# This thing only responds to 'managed' UDP packets -- those sent using the
# two-argument version of UDPSocket#send.  It'll bomb on anything else.
#
# Of course, in the interests of simplicity, there's a real SNMP::Agent
# object underlying this thing, so you can do the usual addition of
# plugins and so forth to make the socket play like the big boys.  Just
# access the agent via #agent.
#
class ICBINASnmpAgent
	attr_reader :last_packet, :agent, :host, :port
	
	# Create the mock agent.  It'll only respond to packets sent to the
	# host/port combo specified here.
	def initialize
		@agent = SNMP::Agent.new
		class << @agent
			public :process_get_request, :process_get_next_request
		end
	end

	def send(data, host, port)
		@host = host
		@port = port
		@last_packet = data
	end
	
	def recv(maxlen, flags = nil)
		return '' if @last_packet.nil?
		
		message = SNMP::Message.decode(@last_packet)
		case message.pdu
			when SNMP::GetRequest
				response = @agent.process_get_request(message)
			when SNMP::GetNextRequest
				response = @agent.process_get_next_request(message)
			else
				response = nil
		end

		response.encode unless response.nil?
	end
end
