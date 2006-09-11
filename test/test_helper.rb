BASE_DIR = File.dirname(File.dirname(File.expand_path(__FILE__)))

$LOAD_PATH.unshift File.join(BASE_DIR, 'lib')

require 'test/unit'
