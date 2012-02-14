require 'win32/registry'

module RAPI
  class Registry
    include Win32::Registry::Constants
    include Enumerable

    attr_accessor :hkey
    attr_accessor :parent
    attr_accessor :keyname
    attr_accessor :disposition

    def self.open(hkey, subkey, desired=KEY_READ)
      subkey = subkey.chomp("\\")
      result_ptr = FFI::MemoryPointer.new(:pointer)
      success = Native::Rapi.CeRegOpenKeyEx(FFI::Pointer.new(hkey.hkey), Util.utf16le(subkey), 0, 0, result_ptr) == 0

      unless success
	raise RAPIException, "Could not open registry key"
      end

      newkey = result_ptr.read_pointer.address
      obj = new(newkey, hkey, subkey, REG_OPENED_EXISTING_KEY)

      if block_given?
	begin
	  yield obj
	ensure
	  obj.close
	end
      else
	obj
      end
    end

    def self.create(hkey, subkey, desired = KEY_ALL_ACCESS, opt = REG_OPTION_RESERVED)
      hkey_ptr = FFI::MemoryPointer.new(:pointer)
      disp_ptr = FFI::MemoryPointer.new(:uint)

      result = Native::Rapi.CeRegCreateKeyEx(FFI::Pointer.new(hkey.hkey), subkey, 0, nil, 0, 0, nil, hkey_ptr, disp_ptr)
      unless result == 0
	raise RAPIException, "Could not create registry key"
      end

      newkey = hkey_ptr.get_pointer(0).address
      disp = disp_ptr.get_uint(0)

      obj = new(newkey, hkey, subkey, disp)
      if block_given?
	begin
	  yield obj
	ensure
	  obj.close
	end
      else
	obj
      end
    end

    def initialize(hkey, parent, keyname, disposition)
      @hkey = hkey
      @phkey = FFI::Pointer.new(@hkey)
      @parent = parent
      @keyname = keyname
      @disposition = disposition
    end

    def create(subkey, desired = KEY_ALL_ACCESS, opt = REG_OPTION_RESERVED, &blk)
      self.class.create(self, subkey, desired, opt, &blk)
    end

    def open(subkey, desired=KEY_READ, &block)
      self.class.open(self, subkey, desired, &block)
    end

    def close
      Native::Rapi.CeRegCloseKey(@phkey)
    end

    def inspect
      "#<RAPI::Registry key=#{name.inspect}>"
    end

    def name
      parent = self
      name = @keyname
      while parent = parent.parent
	name = parent.keyname + "\\" + name
      end
      name
    end

    def delete_value(name)
      Native::Rapi.CeRegDeleteValue(@phkey, Util.utf16le(name))
    end
    alias delete delete_value

    def delete_key(name)
      Native::Rapi.CeRegDeleteKey(@phkey, Util.utf16le(name))
    end

    def [](name, *rtype)
      type, data = read(name, *rtype)
      case type
      when REG_SZ, REG_DWORD, REG_QWORD, REG_MULTI_SZ, REG_EXPAND_SZ
	data
      else
	raise TypeError, "Type #{type} is not supported."
      end
    end

    def read(name, *rtype)
      # For whatever reason, I can't seem to get CeRegQueryValueEx to work...
      # It always returns HRESULT 87 - "The parameter is incorrect".
      type = nil
      data = nil

      each_value do |n, t, d|
	if name.downcase == n.downcase
	  type, data = t, d
	  break
	end
      end

      unless type && data
	raise RAPIException, "Could not find value #{name}"
      end

      unless rtype.empty? or rtype.include?(type)
	raise TypeError, "Type mismatch (expect #{rtype.inspect} but #{type} present)"
      end

      [ type, data ]
    end

    def []=(name, rtype, value = nil)
      if value
	write name, rtype, value
      else
	case value = rtype
	when Integer
	  write name, REG_DWORD, value
	when String
	  write name, REG_SZ, value
	when Array
	  write name, REG_MULTI_SZ, value
	else
	  raise TypeError, "Unexpected type #{value.class}"
	end
      end
      value
    end

    def write(name, type, data)
      case type
      when REG_SZ, REG_EXPAND_SZ
	data = Util.utf16le(data.to_s)
	data_size = data.bytesize
      when REG_MULTI_SZ
	data = data.to_a.map {|d| Util.utf16le(d.to_s)}.join + Util::UTF16LE_NULL
	data_size = data.bytesize
      when REG_BINARY
	data = data.to_s
	data_size = data.bytesize
      when REG_DWORD
	data = Win32::Registry::API.packdw(data.to_i)
	data_size = 4
      when REG_DWORD_BIG_ENDIAN
	data = [data.to_i].pack('N')
	data_size = 4
      when REG_QWORD
	data = Win32::Registry::API.packqw(data.to_i)
	data_size = 8
      else
	raise TypeError, "Unsupported type #{type}"
      end

      Native::Rapi.CeRegSetValueEx(@phkey, Util.utf16le(name), 0, type, data, data_size)
    end

    def each_value
      name_ptr = FFI::MemoryPointer.new(:uint16, 256)
      name_size_ptr = FFI::MemoryPointer.new(:uint)
      name_size_ptr.put_uint(0, 256)

      type_ptr = FFI::MemoryPointer.new(:uint)

      data_ptr = FFI::MemoryPointer.new(:uint16, 0x1000)
      data_size_ptr = FFI::MemoryPointer.new(:uint)

      index = 0
      while true
	result = Native::Rapi.CeRegEnumValue(@phkey, index, name_ptr, name_size_ptr, nil, type_ptr, data_ptr, data_size_ptr)

        if result == Native::ERROR_NO_MORE_ITEMS
	  break
	elsif result != 0
	  raise RAPIException, "Could not enumerate keys"
	end

	index += 1

	name_size = name_size_ptr.get_uint(0)
	name = Util.utf8(name_ptr.get_bytes(0, name_size * 2))
	type = type_ptr.get_uint(0)
	data_size = data_size_ptr.get_uint(0)
	data = data_ptr.get_bytes(0, data_size)

	case type
	when REG_SZ, REG_EXPAND_SZ
	  data = Util.utf8(data)
	when REG_MULTI_SZ
	  puts data.inspect
	  puts data_size
	  data.split(/\00/).map {|str| Util.utf8(str)}
	when REG_BINARY
	  data = data
	when REG_DWORD
	  data = Win32::Registry::API.unpackdw(data)
	when REG_DWORD_BIG_ENDIAN
	  data.unpack('N')[0]
	when REG_QWORD
	  data = Win32::Registry::API.unpackqw(data)
	else
	  raise TypeError, "Type #{type} is not supported."
	end

	name_size_ptr.put_uint(0, 256)
	data_size_ptr.put_uint(0, 0x1000)
	data_ptr.clear
	name_ptr.clear

	yield name, type, data
      end

      index
    end
    alias each each_value

    def each_key(&block)
      self.keys.each(&block)
    end

    def keys
      name_ptr = FFI::MemoryPointer.new(:uint16, 256)
      name_size_ptr = FFI::MemoryPointer.new(:uint)
      name_size_ptr.put_uint(0, 256)

      index = 0
      keys = []
      while true
	result = Native::Rapi.CeRegEnumKeyEx(@phkey, index, name_ptr, name_size_ptr, nil, nil, nil, nil)

        if result == Native::ERROR_NO_MORE_ITEMS
	  break
	elsif result != 0
	  raise RAPIException, "Could not enumerate keys"
	end

	index += 1

	name_size = name_size_ptr.get_uint(0)
	name = Util.utf8(name_ptr.get_bytes(0, name_size * 2))
	name_size_ptr.put_uint(0, 256)

	keys << name
      end

      keys
    end

    # Initialize the top level hkeys
    hkeys = %w{HKEY_CLASSES_ROOT HKEY_CURRENT_USER HKEY_LOCAL_MACHINE HKEY_USERS}
    hkeys.each do |name|
      hkey = Win32::Registry::Constants.const_get(name)
      registry = new(hkey, nil, name, REG_OPENED_EXISTING_KEY)
      const_set(name, registry)
    end
  end
end
