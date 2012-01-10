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
device = RAPI.new
device.connect

# Enumerate some files/directories
some_file = device.glob('\SDMMCDisk\*').first

# Move/delete/copy/download/upload
device.copy some_file.name, some_file.name + '.backup'
device.move some_file.name, '\SDMMCDisk\some_other_file_name'
device.download some_file.name, 'C:\Users\Charles\Desktop\local_copy'
device.upload 'C:\Users\Charles\Desktop\local_copy', '\SDMMCDisk\some_other_file_name', true # overwrite existing
device.delete some_file.name

# Create a process
device.exec "explorer.exe"

# Disconnect
device.disconnect
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
