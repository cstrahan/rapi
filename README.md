About RAPI
==========

Welcome to the **RAPI** project. The [**RAPI** gem](http://rubygems.org/gems/rapi) is an [FFI](https://github.com/ffi/ffi) wrapper for the [Remote API [RAPI]](http://msdn.microsoft.com/en-us/library/aa920177.aspx), providing an intuitive Ruby interface for interacting with mobile devices connected via [ActiveSync](http://en.wikipedia.org/wiki/ActiveSync). **RAPI** is an excellent tool for Windows Mobile developers in need of general automation, or better yet, rolling their own integration test suite in Ruby.


How to Install RAPI
===================

<pre><code>gem install rapi
</code></pre>


How to Use RAPI
===============

```ruby
require 'rapi'

# Create a new RAPI session
RAPI.connect

# Enumerate some files/directories
# Inspect files with the usual suspects (#size, #mtime, #atime, #ctime, etc)
some_file = RAPI.glob('\SDMMCDisk\*').first
some_file.mtime  #=>  2012-02-14 13:50:47 -0600

# Move/delete/copy/download/upload
RAPI.copy(some_file.path, File.join(some_file.path, '.backup'))
RAPI.move(some_file.name, '\SDMMCDisk\some_other_file_name')
RAPI.download(some_file.name, 'C:\Users\Charles\Desktop\local_copy')
RAPI.upload('C:\Users\Charles\Desktop\local_copy', '\SDMMCDisk\some_other_file_name', true) # overwrite existing
RAPI.delete(some_file.name)

# Most of the ::File interface is implemented
temp_file = File.join(RAPI.tmp, "temp.txt")
RAPI.open(temp_file, "a+b") do |f|
  # A bunch of random use cases:
  f.pos = 0
  while buffer=f.read(10)
    print buffer
  end

  f.pos = f.size / 2
  f << "Hello, world!"

  f.truncate(10)
end

# Registry access (similar to Win32::Registry)
RAPI::Registry::HKEY_CURRENT_USER.open("Software") do |key|
  key.each_value do |subkey, type, data|
    puts [subkey, type, data].inspect
  end
end

# Create a process
RAPI.exec "explorer.exe"

# Disconnect
RAPI.disconnect
```

Contributing
============

These things would be awesome to have:

* [Librapi](http://www.synce.org/moin/ComponentOverview) support (for *nix support)
* [RAPI2](http://msdn.microsoft.com/en-us/library/aa920150.aspx) support
* [IRAPIStream](http://msdn.microsoft.com/en-us/library/aa917610.aspx) for streaming [CeRapiInvoke](http://msdn.microsoft.com/en-us/library/aa917422.aspx)


Copyright
=========

Copyright (c) 2011 Charles Strahan. See LICENSE.txt for
further details.
