require 'ffi'
require 'iconv'

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
        Native::Rapi.CeRapiUninit
        raise RAPIException, "Failed to Initialize RAPI"
      end

      if !infinite_timeout
        if (timeout -= 1) < 0
          Native::Kernel32.CloseHandle(init_event)
          Native::Rapi.CeRapiUninit
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

  def exist?(remote_file_name)
    check_connection()

    Native::Rapi::CeGetFileAttributes(to_utf16(remote_file_name)) != 0xFFFFFFFF
  end

  alias exists? exist?

  def download(remote_file_name, local_file_name, overwrite = false)
    check_connection()

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

  def upload(local_file_name, remote_file_name, overwrite = false)
    check_connection()

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

  def copy(existing_file_name, new_file_name, overwrite = false)
    check_connection()

    if Native::Rapi.CeCopyFile(to_utf16(existing_file_name), to_utf16(new_file_name), overwrite ? 0 : 1) == 0
      raise RAPIException, "Cannot copy file"
    end

    true
  end

  def delete(file_name)
    check_connection()

    if Native::Rapi.CeDeleteFile(to_utf16(file_name)) == 0
      raise RAPIException, "Could not delete file"
    end

    true
  end

  def move(existing_file_name, new_file_name)
    check_connection()

    if Native::Rapi.CeMoveFile(to_utf16(existing_file_name), to_utf16(new_file_name)) == 0
      raise RAPIException, "Cannot move file"
    end

    true
  end

  def get_attributes(file_name)
    check_connection()

    ret = Native::Rapi.CeGetFileAttributes(to_utf16(file_name))
    if ret == 0xFFFFFFFF
      raise RAPIException, "Could not get file attributes"
    end

    FileAttributes.new(ret)
  end

  alias get_attrs get_attributes

  def set_attributes(file_name, attributes)
    check_connection()

    if Native::Rapi.CeSetFileAttributes(to_utf16(file_name), attributes.to_i) == 0
      raise RAPIExcpetion, "Cannot set device file attributes"
    end
  end

  alias set_attrs set_attributes

  def search(file_name)
    check_connection()

    find_data = Native::Rapi::CE_FIND_DATA.new
    
    file_infos = []
    handle = Native::Rapi.CeFindFirstFile(to_utf16(file_name), find_data)

    if handle != Native::INVALID_HANDLE
      file_infos << FileInformation.new(file_name, find_data)
      find_data.pointer.clear

      while Native::Rapi.CeFindNextFile(handle, find_data) != 0
        file_infos << FileInformation.new(file_name, find_data)
        find_data.pointer.clear
      end

      Native::Rapi.CeFindClose(handle)
    end

    file_infos
  end

  alias glob search

  def exec(file_name, *args)
    check_connection

    args = if args.empty?
             nil
           else
             args.join(' ')
           end

    pi = Native::Rapi::PROCESS_INFORMATION.new

    if Native::Rapi.CeCreateProcess(to_utf16(file_name), to_utf16(args), nil, nil, 0, 0, nil, nil, nil, pi) == 0
      errnum = Native::Rapi.CeGetLastError
      handle_hresult! errnum
    end

    ProcessInformation.new(pi)
  end

  private

  def check_connection
    unless connected?
      raise RAPIException, "Cannot perform operation while disconnected"
    end
  end

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
      return nil if str.nil?
      str.encode("UTF-16LE") + "\0\0".force_encoding("UTF-16LE")
    end
  else
    def to_utf16(str)
      return nil if str.nil?
      Iconv.conv("UTF-16LE", "ASCII", str) + "\0\0"
    end
  end

  public

  class ProcessInformation
    attr_reader :process_handle
    attr_reader :thread_handle
    attr_reader :process_id
    attr_reader :thread_id

    def initialize(process_information)
      @process_handle = process_information[:hProcess]
      @thread_handle  = process_information[:hThread]
      @process_id     = process_information[:dwProcessId]
      @thread_id      = process_information[:dwThreadId]
    end
  end

  class FileInformation
    attr_reader :attributes
    attr_reader :create_time
    attr_reader :last_access_time
    attr_reader :last_write_time
    attr_reader :size
    attr_reader :name
    attr_reader :path

    def initialize(search_term, ce_find_data)
      @attributes         = FileAttributes.new(ce_find_data[:dwFileAttributes])
      @create_time        = ce_find_data[:ftCreationTime]
      @last_access_time   = ce_find_data[:ftLastAccessTime]
      @last_write_time    = ce_find_data[:ftLastWriteTime]
      @name               = encode(ce_find_data[:cFileName].to_ptr.get_bytes(0, 260))
      @size               = ce_find_data[:nFileSizeHigh] << 32 &&
                            ce_find_data[:nFileSizeLow]

      dir = File.expand_path("/" + File.dirname(search_term)).gsub(%r{^([a-z]:|\\|/|\.)}i, '')
      @path =  File.join(dir, @name)
    end

    private

    if RUBY_VERSION =~ /^1\.9\.\d/
      def encode(path)
        path.force_encoding("UTF-16LE").strip.encode("UTF-8")
      end
    else
      def encode(path)
        Iconv.conv("ASCII", "UTF-16LE", path).strip
      end
    end
  end

  class Enum

    private

    def self.enum_attr(name, num)
      name = name.to_s

      define_method(name + "?") do
        @attrs & num != 0
      end

      define_method(name + "=") do |set|
        if set
          @attrs |= num
        else
          @attrs &= ~num
        end
      end
    end

    public

    def initialize(attrs = 0)
      @attrs = attrs.to_i
    end

    def to_i
      @attrs
    end
  end

  class FileAttributes < Enum
    enum_attr :readonly,       0x0001
    enum_attr :hidden,         0x0002
    enum_attr :system,         0x0004
    enum_attr :directory,      0x0010
    enum_attr :archive,        0x0020
    enum_attr :in_rom,         0x0040
    enum_attr :normal,         0x0080
    enum_attr :temporary,      0x0100
    enum_attr :sparse,         0x0200
    enum_attr :reparse_point,  0x0400
    enum_attr :compressed,     0x0800
    enum_attr :rom_module,     0x2000
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

    FILE_SHARE_READ = 0x00000001
    CREATE_NEW      = 0x00000001
    CREATE_ALWAYS   = 0x00000002
    GENERIC_WRITE   = 0x40000000
    GENERIC_READ    = 0x80000000
    OPEN_EXISTING   = 0x00000003
    FILE_ATTRIBUTE_NORMAL = 0x80
    INVALID_HANDLE  = FFI::Pointer.new(-1)

    class FILETIME
      extend FFI::DataConverter
      native_type :uint64

      def self.from_native(val, ctx)
        Time.at((val * 1.0e-07) + Time.new(1601).to_f)
      end

      def self.to_native(val, ctx)
        ((val.to_f - Time.new(1601).to_f) / 1.0e-07).to_i 
      end
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

      class CE_FIND_DATA < FFI::Struct
        layout  :dwFileAttributes,  :uint,          0,
                :ftCreationTime,    FILETIME,       4,
                :ftLastAccessTime,  FILETIME,      12,
                :ftLastWriteTime,   FILETIME,      20,
                :nFileSizeHigh,     :uint,         28,
                :nFileSizeLow,      :uint,         32,
                :dwOID,             :uint,         36,
                :cFileName,         [:uint8, 260], 40
      end

      class PROCESS_INFORMATION < FFI::Struct
        layout  :hProcess,       :pointer,
                :hThread,        :pointer,
                :dwProcessId,    :uint,
                :dwThreadId,     :uint
      end

      attach_function :CeRapiInitEx, [RAPIINIT.by_ref], :int
      attach_function :CeRapiUninit, [], :int
      attach_function :CeRapiGetError, [], :int
      attach_function :CeCloseHandle, [:pointer], :int
      attach_function :CeWriteFile, [:pointer, :pointer, :int, :pointer, :int], :int
      attach_function :CeReadFile, [:pointer, :pointer, :int, :pointer, :int], :int
      attach_function :CeRapiFreeBuffer, [:pointer], :void
      attach_function :CeGetFileAttributes, [:pointer], :uint
      attach_function :CeCreateFile, [:pointer, :uint, :int, :int, :int, :int, :int], :pointer
      attach_function :CeCopyFile, [:pointer, :pointer, :int], :int
      attach_function :CeDeleteFile, [:pointer], :int
      attach_function :CeGetFileAttributes, [:pointer], :uint
      attach_function :CeSetFileAttributes, [:pointer, :uint], :int
      attach_function :CeFindFirstFile, [:pointer, CE_FIND_DATA.by_ref], :pointer
      attach_function :CeFindNextFile, [:pointer, CE_FIND_DATA.by_ref], :int
      attach_function :CeFindClose, [:pointer], :int
      attach_function :CeCreateProcess, [:pointer, :pointer, :pointer, :pointer, :int, :int, :pointer, :pointer, :pointer, PROCESS_INFORMATION.ptr], :int
      attach_function :CeGetLastError, [], :int
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
