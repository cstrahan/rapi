require 'ffi'

class RAPI

  attr_accessor :copy_buffer_size

  def initialize
    @connected = false
    @copy_buffer_size = 0x1000
  end

  def connected?
    @connected
  end

  def connect(timeout_seconds = 1)
    self.disconnect if connected?

    init = Native::Rapi::RAPIINIT.new
    init[:cbSize] = Native::Rapi::RAPIINIT.size
    ret = Native::Rapi.CeRapiInitEx(init)
    handle_hresult! ret
    init_event = init[:heRapiInit]

    timeout = timeout_seconds * 4
    infinite_timeout = timeout < 0

    begin
      ret = Native::Kernel32.WaitForSingleObject(init_event, 250)

      if ret == Native::WAIT_FAILED || ret == Native::WAIT_ABANDONED
        Native::Kernel32.CloseHandle(init_event)
        raise RAPIException, "Failed to Initialize RAPI"
      end

      if !infinite_timeout
        if (timeout -= 1) < 0
          Native::Kernel32.CloseHandle(init_event)
          raise RAPIException, "Timeout waiting for device connection"
        end
      end
    end while ret != Native::WAIT_OBJECT_0

    @connected = true
    Native::Kernel32.CloseHandle(init_event)

    true
  end

  def disconnect
    if connected?
      Native::Rapi.CeRapiUninit
      @connected = false
    end

    true
  end

  def device_file_exists?(remote_file_name)
    path = to_utf16(remote_file_name)
    Native::Rapi::CeGetFileAttributes(path) != 0xFFFFFFFF
  end

  def copy_file_from_device(remote_file_name, local_file_name, overwrite = false)

    if !overwrite && File.exists?(local_file_name)
      raise RAPIException, "A local file with the given name already exists"
    end

    remote_file = Native::Rapi.CeCreateFile(to_utf16(remote_file_name), Native::GENERIC_READ, 0, 0, Native::OPEN_EXISTING, Native::FILE_ATTRIBUTE_NORMAL, 0)
    if remote_file == Native::INVALID_HANDLE
      raise RAPIException, "Could not open remote file"
    end

    File.open(local_file_name, "wb") do |f|
      buffer = FFI::MemoryPointer.new(1, @copy_buffer_size)
      bytes_read_ptr = FFI::MemoryPointer.new(FFI::Type::INT.size)

      while true
        ret = Native::Rapi.CeReadFile(remote_file, buffer, buffer.size, bytes_read_ptr, 0)

        bytes_read = bytes_read_ptr.get_int(0)

        if bytes_read != 0 && ret == 0
          buffer.free
          bytes_read_ptr.free
          Native::Rapi.CeCloseHandle(remote_file)
          raise RAPIException, "Failed to read device data"
        elsif bytes_read == 0
          break
        end

        f << buffer.get_bytes(0, bytes_read)
      end

      buffer.free
      bytes_read_ptr.free
      Native::Rapi.CeCloseHandle(remote_file)
    end

    true
  end

  def copy_file_to_device(local_file_name, remote_file_name, overwrite = false)
    
    create = overwrite ? Native::CREATE_ALWAYS : Native::CREATE_NEW
    remote_file = Native::Rapi.CeCreateFile(to_utf16(remote_file_name), Native::GENERIC_WRITE, 0, 0, create, Native::FILE_ATTRIBUTE_NORMAL, 0)

    if remote_file == Native::INVALID_HANDLE
      raise RAPIException, "Could not create remote file"
    end

    if File.size(local_file_name) != 0
      File.open(local_file_name, "rb") do |f|
        while buffer = f.read(copy_buffer_size)
          if Native::Rapi.CeWriteFile(remote_file, buffer, buffer.size, nil, 0) == 0
            Native::Rapi.CeCloseHandle(remote_file)
            raise RAPIException, "Could not write to remote file"
          end
        end
      end
    end

    Native::Rapi.CeCloseHandle(remote_file)

    true
  end

  private

  def handle_hresult!(hresult)
    if hresult != 0
      msg_ptr = FFI::MemoryPointer.new(FFI::Pointer)
      format = Native::FORMAT_MESSAGE_ALLOCATE_BUFFER | Native::FORMAT_MESSAGE_FROM_SYSTEM | Native::FORMAT_MESSAGE_IGNORE_INSERTS
      len = Native::Kernel32.FormatMessageA(format, nil, hresult, 0, msg_ptr, 0, nil)
      if len == 0
        msg = "Error {hresult} (0x#{hresult.to_s(16).upcase})"
      else
        msg = msg_ptr.get_pointer(0).get_string(0)
      end
      Native::Kernel32.LocalFree(msg_ptr.get_pointer(0))
      msg_ptr.free
      raise RAPIException, msg
    end
  end

  if RUBY_VERSION =~ /^1\.9\.\d/
    def to_utf16(str)
      str.encode("UTF-16LE")
    end
  else
    require 'iconv'
    def to_utf16(str)
      Iconv.conv("UTF-16LE", "ASCII", str)
    end
  end

  public

  class RAPIException < Exception
  end

  module Native

    # Winbase.h
    WAIT_ABANDONED = 0x00000080
    WAIT_FAILED    = 0xFFFFFFFF
    WAIT_TIMEOUT   = 0x00000102
    WAIT_OBJECT_0  = 0x00000000
 
    FORMAT_MESSAGE_FROM_SYSTEM     = 0x00001000
    FORMAT_MESSAGE_FROM_HMODULE    = 0x00000800
    FORMAT_MESSAGE_IGNORE_INSERTS  = 0x00000200
    FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100

    FILE_SHARE_READ = 0x00000001
    CREATE_NEW      = 0x00000001
    CREATE_ALWAYS   = 0x00000002
    GENERIC_WRITE   = 0x40000000
    GENERIC_READ    = 0x80000000
    OPEN_EXISTING   = 0x00000003
    FILE_ATTRIBUTE_NORMAL = 0x80
    INVALID_HANDLE  = FFI::Pointer.new(-1)

    module Util
    end

    module Rapi
      extend FFI::Library
      ffi_lib 'rapi.dll'
      ffi_convention :stdcall

      class RAPIINIT < FFI::Struct
        layout  :cbSize,     :int,
                :heRapiInit, :pointer,
                :hrRapiInit, :int
      end

      attach_function 'CeRapiInitEx', [RAPIINIT.by_ref], :int
      attach_function 'CeRapiUninit', [], :int
      attach_function 'CeRapiGetError', [], :int
      attach_function 'CeRapiUninit', [], :int
      attach_function 'CeCloseHandle', [:pointer], :int
      attach_function 'CeWriteFile', [:pointer, :pointer, :int, :pointer, :int], :int
      attach_function 'CeReadFile', [:pointer, :pointer, :int, :pointer, :int], :int
      attach_function 'CeRapiFreeBuffer', [:pointer], :void
      attach_function 'CeGetFileAttributes', [:pointer], :uint
      attach_function 'CeCreateFile', [:pointer, :uint, :int, :int, :int, :int, :int], :pointer
    end

    module Kernel32
      extend FFI::Library
      ffi_lib 'kernel32'
      ffi_convention :stdcall

      @blocking = true
      attach_function :WaitForSingleObject, [:pointer, :uint], :uint
      attach_function :FormatMessageW, [:int, :pointer, :int, :int, :pointer, :int, :pointer], :int
      attach_function :FormatMessageA, [:int, :pointer, :int, :int, :pointer, :int, :pointer], :int
      attach_function :CloseHandle, [:pointer], :int
      attach_function :LocalFree, [:pointer], :pointer
    end
  end
end
