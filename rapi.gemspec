# -*- encoding: utf-8 -*-

$:.unshift File.expand_path("../lib", __FILE__)
require 'rapi/version'

Gem::Specification.new do |s|
  s.add_development_dependency 'bundler'
  s.add_development_dependency 'rake'

  s.name = 'rapi'
  s.version = RAPI::VERSION
  s.summary = %q{A Remote API (RAPI) interface.}
  s.description = %q{A Remote API (RAPI) interface.}
  s.authors = ['Charles Strahan']
  s.email = 'charles.c.strahan@gmail.com'
  s.files = `git ls-files`.split("\n")
  s.homepage = 'http://github.com/cstrahan/rapi'

  s.rdoc_options = ['--charset=UTF-8']
  s.extra_rdoc_files = [
    "LICENSE.txt",
    "README.rdoc"
  ]

  s.licenses = ["MIT"]
  s.require_paths = ['lib']
  s.required_rubygems_version = Gem::Requirement.new('>= 1.3.6')
  s.test_files = `git ls-files -- {test,spec,features}/*`.split("\n")
end
