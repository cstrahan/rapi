# encoding: utf-8
require 'rubygems'

task :console do
  $:.unshift(File.expand_path("../lib", __FILE__))
  require 'rapi'
  
  if ARGV[1]
    begin
      script = File.readlines(ARGV[1]).join("\n")
      val = eval(script, binding, ARGV[1])
      puts "#=>#{val.inspect}"
    rescue Exception => er
      puts er.message
      puts er.backtrace[0...8]
    end
  end
  
  require 'irb'
  ARGV.clear
  IRB.start
end

require 'jeweler'
Jeweler::Tasks.new do |gem|
  gem.name = "rapi"
  gem.homepage = "http://github.com/cstrahan/rapi"
  gem.license = "MIT"
  gem.summary = %Q{A Remote API (RAPI) interface.}
  gem.description = %Q{A Remote API (RAPI) interface.}
  gem.email = "charles.c.strahan@gmail.com"
  gem.authors = ["Charles Strahan"]
end
Jeweler::RubygemsDotOrgTasks.new

require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/test_*.rb'
  test.verbose = true
end