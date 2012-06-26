# encoding: utf-8
$:.unshift File.expand_path("../lib", __FILE__)

require 'rapi/version'
require 'rspec/core/rake_task'

# build, install, release
Bundler::GemHelper.install_tasks

RSpec::Core::RakeTask.new do |t|
  t.pattern = "./spec/**/*_spec.rb"
end

task :console do
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

# Inspired by `require_clean_work_tree'
# http://stackoverflow.com/questions/3878624
def work_tree_clean?
  `git update-index -q --ignore-submodules --refresh`
  if `git diff-files --quiet --ignore-submodules --` && !$?.success?
    false
  elsif `git diff-index --cached --quiet HEAD --ignore-submodules --` && !$?.success?
    false
  else
    true
  end
end

desc "Create tag v#{RAPI::VERSION}"
task :tag do
  if work_tree_clean?
    sh "git tag v#{RAPI::VERSION}"
    sh "git push origin v#{RAPI::VERSION}"
  else
    fail "Your work tree isn't clean!"
  end
end
