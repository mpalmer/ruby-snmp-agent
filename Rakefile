desc "Run all the tests"
task :default do
	testdir = File.dirname(File.expand_path(__FILE__)) + "/test/*_test.rb"
	Dir[testdir].each { |f| puts "Loading #{f}"; load f }
end
