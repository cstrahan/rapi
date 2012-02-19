require 'simplecov'
require 'rapi'

module TempHelper
  def tmp(parts=[])
    File.join(RAPI.tmp, "rapi_test_dir", *parts)
  end
end
