require 'ffi'

class RAPI

  def initialize
    @connected = false
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
    end while ret != 0

    @connected = true
    Native::Kernel32.CloseHandle(init_event)

    nil
  end

  def disconnect
    if connected?
      Native::Rapi.CeRapiUninit
      @connected = false
    end

    nil
  end

  def device_file_exists?(remote_file_name)
  end

  def handle_hresult!(hresult)
    if hresult != 0
      # TODO: Consider using FORMAT_MESSAGE_ALLOCATE_BUFFER & LocalFree
      msg = " " * 1024
      len = Native::Kernel32.FormatMessageA(Native::Kernel32::FORMAT_MESSAGE_FROM_SYSTEM | Native::Kernel32::FORMAT_MESSAGE_IGNORE_INSERTS, nil, hresult, 0, msg, 1024, nil)
      msg = msg[0..len-3] # remove \r\n\000
      raise RAPIException, msg
    end
  end

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

    module Rapi
      extend FFI::Library
      ffi_lib 'rapi.dll'
      ffi_convention :stdcall

      class RAPIINIT < FFI::Struct
        layout  :cbSize,     :int,
                :heRapiInit, :pointer,
                :hrRapiInit, :int
      end

      @blocking = true
      attach_function 'CeRapiInit', [], :int
      attach_function 'CeRapiInitEx', [RAPIINIT.by_ref], :int
      attach_function 'CeRapiUninit', [], :int
      attach_function 'CeRapiGetError', [], :int
      attach_function 'CeRapiUninit', [], :int
      attach_function 'CeRapiUninit', [], :int
      attach_function 'CeWriteFile', [:pointer, :pointer, :int, :pointer, :int], :int
      attach_function 'CeRapiFreeBuffer', [:pointer], :void
    end

    module Kernel32

      extend FFI::Library
      ffi_lib 'kernel32'
      ffi_convention :stdcall

      attach_function :FormatMessageA, [:int, :pointer, :int, :int, :string, :int, :pointer], :int
      @blocking = true
      attach_function :WaitForSingleObject, [:pointer, :uint], :uint
      attach_function :CloseHandle, [:pointer], :int

    end
  end
end
