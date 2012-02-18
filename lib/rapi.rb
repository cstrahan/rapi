require 'ffi'
require 'iconv'

require 'rapi/registry'
require 'rapi/remote_file'

module RAPI
  @copy_buffer_size = 0x1000

  class << self
    attr_accessor :copy_buffer_size

    def connected?
      # Try calling an arbitrary function.
      Native::Rapi.CeGetFileAttributes(Util.utf16le(""))
      Util.error != Native::CONNECTION_LOST
    end

    def connect(timeout_seconds = 1)
      self.disconnect if connected?

      init = Native::Rapi::RAPIINIT.new
      init[:cbSize] = Native::Rapi::RAPIINIT.size
      ret = Native::Rapi.CeRapiInitEx(init)
      Util.handle_hresult! ret
      init_event = init[:heRapiInit]

      timeout = timeout_seconds * 4
      infinite_timeout = timeout < 0

      begin
        ret = Native::Kernel32.WaitForSingleObject(init_event, 250)

        if ret == Native::WAIT_FAILED || ret == Native::WAIT_ABANDONED
          Native::Rapi.CeRapiUninit
          raise RAPIError, "Failed to Initialize RAPI."
        end

        if !infinite_timeout
          if (timeout -= 1) < 0
            Native::Rapi.CeRapiUninit
            raise RAPIError, "Timeout waiting for device connection."
          end
        end
      end while ret != Native::WAIT_OBJECT_0

      @connected = true

      true

    ensure

      Native::Kernel32.CloseHandle(init_event) if init_event
      init.to_ptr.free
    end

    def disconnect
      Native::Rapi.CeRapiUninit

      true
    end

    def exist?(remote_file_name)
      attrs = Native::Rapi.CeGetFileAttributes(Util.utf16le(remote_file_name))

      if attrs != 0xFFFFFFFF
        true
      else
        err = Util.error
        if err == Native::FILE_NOT_FOUND || err == Native::PATH_NOT_FOUND
          false
        else
          Util.handle_hresult! err
        end
      end
    end

    alias exists? exist?

    def mkdir(path)
      success = Native::Rapi.CeCreateDirectory(Util.utf16le(path), nil) != 0

      unless success
        Util.handle_hresult! Util.error, "Could not create directory."
      end

      true
    end

    def download(remote_file_name, local_file_name, overwrite = false)
      if !overwrite && File.exists?(local_file_name)
        raise RAPIError, "A local file with the given name already exists."
      end

      handle = Native::Rapi.CeCreateFile(Util.utf16le(remote_file_name), Native::GENERIC_READ, 0, 0, Native::OPEN_EXISTING, Native::FILE_ATTRIBUTE_NORMAL, 0)
      unless handle.valid?
        Util.handle_hresult! Util.error, "Could not open remote file."
      end

      mode = overwrite ? "wb" : "r+b"
      buffer = FFI::MemoryPointer.new(:char, @copy_buffer_size)
      bytes_read_ptr = FFI::MemoryPointer.new(:uint)

      File.open(local_file_name, "wb") do |f|
        while true
          success = Native::Rapi.CeReadFile(handle, buffer, buffer.size, bytes_read_ptr, 0) != 0
          unless success
            Util.handle_hresult! Util.error, "Failed to read device data."
          end

          bytes_read = bytes_read_ptr.get_int(0)

          if bytes_read != 0 && !success
            err = Util.error
            Native::Rapi.CeCloseHandle(handle)
            Util.handle_hresult! err, "Failed to read device data."
          elsif bytes_read == 0
            break
          end

          f << buffer.get_bytes(0, bytes_read)
        end

        f.truncate(f.pos)
      end

      true

    ensure
      buffer.free if buffer
      bytes_read_ptr.free if bytes_read_ptr
      handle.close if handle
    end

    def upload(local_file_name, remote_file_name, overwrite = false)
      create = overwrite ? Native::CREATE_ALWAYS : Native::CREATE_NEW
      handle = Native::Rapi.CeCreateFile(Util.utf16le(remote_file_name), Native::GENERIC_WRITE, 0, 0, create, Native::FILE_ATTRIBUTE_NORMAL, 0)

      unless handle.valid?
        raise RAPIError, "Could not create remote file."
      end

      if File.size(local_file_name) != 0
        File.open(local_file_name, "rb") do |f|
          while buffer = f.read(copy_buffer_size)
            if Native::Rapi.CeWriteFile(handle, buffer, buffer.size, nil, 0) == 0
              Native::Rapi.CeCloseHandle(handle)
              raise RAPIError, "Could not write to remote file."
            end
          end
        end
      end

      true

    ensure
      handle.close
    end

    def copy(existing_file_name, new_file_name, overwrite = false)
      success = Native::Rapi.CeCopyFile(Util.utf16le(existing_file_name), Util.utf16le(new_file_name), overwrite ? 0 : 1) != 0

      unless success
        Util.handle_hresult! Util.error, "Could not copy file."
      end

      true
    end

    def delete(file_name)
      attrs = get_attrs(file_name) rescue nil

      unless attrs
        Util.handle_hresult! Native::FILE_NOT_FOUND, "Could not delete file."
      end

      if attrs.directory?
        success = Native::Rapi.CeRemoveDirectory(Util.utf16le(file_name)) != 0
      else
        success = Native::Rapi.CeDeleteFile(Util.utf16le(file_name)) != 0
      end

      unless success
        Util.handle_hresult! Util.error, "Could not delete file."
      end

      true
    end

    alias rm delete

    def rm_rf(path)
      search(path).each do |file|
        rm_rf(File.join(file.path, "*")) if file.directory?
        delete(file.path)
      end
    end

    def move(existing_file_name, new_file_name)
      success = Native::Rapi.CeMoveFile(Util.utf16le(existing_file_name), Util.utf16le(new_file_name)) != 0

      unless success
        Util.handle_hresult! Util.error, "Could not move file."
      end

      true
    end

    def get_attributes(file_name)
      ret = Native::Rapi.CeGetFileAttributes(Util.utf16le(file_name))
      success = ret != 0xFFFFFFFF

      unless success
        Util.handle_hresult! Util.error, "Could not get file attributes."
      end

      FileAttributes.new(ret)
    end

    alias get_attrs get_attributes

    def set_attributes(file_name, attributes)
      success = Native::Rapi.CeSetFileAttributes(Util.utf16le(file_name), attributes.to_i) != 0

      unless success
        Util.handle_hresult! Util.error, "Could not set device file attributes."
      end

      true
    end

    alias set_attrs set_attributes

    def search(search_term)
      file_infos = []

      ppFindDataArray = FFI::MemoryPointer.new(:pointer)
      count_ptr = FFI::MemoryPointer.new(:uint)
      success = Native::Rapi.CeFindAllFiles(Util.utf16le(search_term), 255, count_ptr, ppFindDataArray) != 0

      if !success && Util.error == Native::CONNECTION_LOST
        Util.handle_hresult! Native::CONNECTION_LOST
      end

      begin
        count = count_ptr.get_uint(0)
        if count > 0
          array_ptr = FFI::Pointer.new(Native::Rapi::CE_FIND_DATA, ppFindDataArray.get_pointer(0))
          directory = Util.sanitize_path(search_term)

          (0...count).each do |n|
            info = FileInformation.new(directory, Native::Rapi::CE_FIND_DATA.new(array_ptr[n]))
            file_infos << info
          end
        end
      end

      file_infos

    ensure
      ppFindDataArray.free if ppFindDataArray
      array_ptr.free if array_ptr
      count_ptr.free if count_ptr
      Native::Rapi.CeRapiFreeBuffer(array_ptr) if array_ptr
    end

    alias glob search

    def exec(file_name, *args)
      args = if args.empty?
               nil
             else
               args.join(' ')
             end

      pi = Native::Rapi::PROCESS_INFORMATION.new

      if Native::Rapi.CeCreateProcess(Util.utf16le(file_name), Util.utf16le(args), nil, nil, 0, 0, nil, nil, nil, pi) == 0
        errnum = Native::Rapi.CeGetLastError
        Util.handle_hresult! errnum
      end

      ProcessInformation.new(pi)
    end

    def tmp
      buffer = FFI::MemoryPointer.new(:uint16, Native::MAX_PATH + 1)
      temp_path = nil
      if Native::Rapi.CeGetTempPath(Native::MAX_PATH, buffer) != 0
        temp_path = Util.utf8(buffer.get_bytes(0, Native::MAX_PATH * 2))
      end

      temp_path

    ensure
      buffer.free if buffer
    end

    def open(path, *rest)
      file = RemoteFile.new(path, *rest)
      if block_given?
        begin
          yield file
        ensure
          file.close
        end
      else
        file
      end
    end

    def os
      os = Native::Rapi::CEOSVERSIONINFO.new
      os[:dwOSVersionInfoSize] = Native::Rapi::CEOSVERSIONINFO.size
      success = Native::Rapi.CeGetVersionEx(os) != 0
      unless success
        raise RAPIError, "Error retrieving version information."
      end

      OSVersionInfo.new(os)
    end
  end

  module Util
    def self.handle_hresult!(hresult, msg="")
      if hresult == Native::CONNECTION_LOST
        sep = msg.size > 0 ? " " : ""
        msg += sep + "The RAPI connection was lost."
        raise RAPIError.new(msg)
      elsif hresult != 0
        raise RAPIError.new(msg, hresult)
      end
    end

    def self.error
      rapi_error = Native::Rapi.CeRapiGetError

      if rapi_error != 0
        rapi_error
      else
        Native::Rapi.CeGetLastError
      end
    end

    def self.format_msg(errnum)
      msg_ptr = FFI::MemoryPointer.new(FFI::Pointer)
      format = Native::FORMAT_MESSAGE_ALLOCATE_BUFFER | Native::FORMAT_MESSAGE_FROM_SYSTEM | Native::FORMAT_MESSAGE_IGNORE_INSERTS
      len = Native::Kernel32.FormatMessageA(format, nil, errnum, 0, msg_ptr, 0, nil)
      if len == 0
        msg = "Error {hresult} (0x#{hresult.to_s(16).upcase})"
      else
        msg = msg_ptr.get_pointer(0).get_string(0).rstrip
      end
      Native::Kernel32.LocalFree(msg_ptr.get_pointer(0))
      msg_ptr.free

      msg
    end

    def self.sanitize_path(path)
      # Remove wildcards and such
      path = File.expand_path("/" + File.dirname(path)).gsub(%r{^([a-z]:|\\|/|\.)}i, '')

      # Make sure each part is properly cased
      clean_path = ""

      pieces = path.split(%r{/|\\}).select {|p| !p.empty?}

      pieces.each do |piece|
        search_term = clean_path + "/" + piece

        ppFindDataArray = FFI::MemoryPointer.new(:pointer)
        count_ptr = FFI::MemoryPointer.new(:uint)
        success = Native::Rapi.CeFindAllFiles(Util.utf16le(search_term), 255, count_ptr, ppFindDataArray) != 0
        if success
          count = count_ptr.get_uint(0)

          if count > 0
            array_ptr = FFI::Pointer.new(Native::Rapi::CE_FIND_DATA, ppFindDataArray.get_pointer(0))

            info = FileInformation.new("", Native::Rapi::CE_FIND_DATA.new(array_ptr[0]))
            clean_path << "/" + info.name

            Native::Rapi.CeRapiFreeBuffer(array_ptr)
          end
        else
          raise RAPIError, "Could not read file info."
        end
      end

      clean_path
    end

    if RUBY_VERSION =~ /^1\.9\.\d/
      UTF16LE_NULL = "\0\0".force_encoding("UTF-16LE")

      def self.utf16le(str)
        return nil if str.nil?
        str.encode("UTF-16LE") + UTF16LE_NULL
      end

      def self.utf8(path)
        if index = path.index("\0\0")
          index += 1 if index.odd?
          path = path.slice(0, index)
        end

        path.force_encoding("UTF-16LE").encode("UTF-8")
      end
    else
      UTF16LE_NULL = "\0\0"

      def self.utf16le(str)
        return nil if str.nil?
        Iconv.conv("UTF-16LE", "ASCII", str) + UTF16LE_NULL
      end

      def self.utf8(path)
        if index = path.index("\0\0")
          index += 1 if index.odd?
          path = path.slice(0, index)
        end

        Iconv.conv("ASCII", "UTF-16LE", path)
      end
    end
  end

  class OSVersionInfo
    attr_reader :major
    attr_reader :minor
    attr_reader :build
    attr_reader :version

    def initialize(struct)
      @major = struct[:dwMajorVersion]
      @minor = struct[:dwMinorVersion]
      @build = struct[:dwBuildNumber]
      @version = Util.utf8(struct[:szCSDVersion].to_ptr.get_bytes(0, 256)).freeze
    end

    def inspect
      "#<RAPI::OSVersionInfo version=#{major}.#{minor}.#{build}>"
    end
  end

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
    attr_reader :ctime
    attr_reader :atime
    attr_reader :mtime
    attr_reader :size
    attr_reader :name
    attr_reader :path

    def initialize(directory, ce_find_data)
      @attributes = FileAttributes.new(ce_find_data[:dwFileAttributes]).freeze
      @ctime      = ce_find_data[:ftCreationTime].freeze
      @atime      = ce_find_data[:ftLastAccessTime].freeze
      @mtime      = ce_find_data[:ftLastWriteTime].freeze
      @name       = Util.utf8(ce_find_data[:cFileName].to_ptr.get_bytes(0, Native::MAX_PATH * 2)).freeze
      @size       = ce_find_data[:nFileSizeHigh] << 32 &&
                    ce_find_data[:nFileSizeLow]

      @path =  File.join(directory, @name).freeze
    end

    def file?
      self.attributes.file?
    end

    def directory?
      self.attributes.directory?
    end

    def <=>(other_info)
      @mtime <=> other_info.mtime if other_info.respond_to?(:mtime)
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

  class RAPIError < StandardError
    def initialize(msg, code=nil)
      code, msg = msg, "" if msg.kind_of?(Integer)

      if code
        msg += " " + Util.format_msg(code)
      end

      super msg.strip
    end
  end

  module Native

    # Winbase.h
    WAIT_ABANDONED = 0x00000080
    WAIT_FAILED    = 0xFFFFFFFF
    WAIT_TIMEOUT   = 0x00000102
    WAIT_OBJECT_0  = 0x00000000

    INVALID_FILE_SIZE = 0xFFFFFFFF

    MAX_PATH = 260

    FORMAT_MESSAGE_FROM_SYSTEM     = 0x00001000
    FORMAT_MESSAGE_FROM_HMODULE    = 0x00000800
    FORMAT_MESSAGE_IGNORE_INSERTS  = 0x00000200
    FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100

    GENERIC_READ      = 0x80000000
    GENERIC_WRITE     = 0x40000000

    FILE_SHARE_READ   = 0x00000001
    FILE_SHARE_WRITE  = 0x00000002

    ERROR_NO_MORE_ITEMS = 0X0103

    CREATE_NEW        = 0x00000001
    CREATE_ALWAYS     = 0x00000002
    OPEN_EXISTING     = 0x00000003
    OPEN_ALWAYS       = 0x00000004
    TRUNCATE_EXISTING = 0x00000005

    INVALID_HANDLE = FFI::Pointer.new(-1)

    FILE_BEGIN   = 0x00
    FILE_CURRENT = 0x01
    FILE_END     = 0x02

    FILE_ATTRIBUTE_ARCHIVE       = 0x00000020;
    FILE_ATTRIBUTE_COMPRESSED    = 0x00000800;
    FILE_ATTRIBUTE_DIRECTORY     = 0x00000010;
    FILE_ATTRIBUTE_ENCRYPTED     = 0x00004000;
    FILE_ATTRIBUTE_HIDDEN        = 0x00000002;
    FILE_ATTRIBUTE_INROM         = 0x00000040;
    FILE_ATTRIBUTE_NORMAL        = 0x00000080;
    FILE_ATTRIBUTE_READONLY      = 0x00000001;
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
    FILE_ATTRIBUTE_ROMMODULE     = 0x00002000;
    FILE_ATTRIBUTE_SPARSE_FILE   = 0x00000200;
    FILE_ATTRIBUTE_SYSTEM        = 0x00000004;
    FILE_ATTRIBUTE_TEMPORARY     = 0x00000100;

    FILE_FLAG_WRITE_THROUGH   = 0x80000000;
    FILE_FLAG_OVERLAPPED      = 0x40000000;
    FILE_FLAG_RANDOM_ACCESS   = 0x10000000;
    FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;

    FAF_ATTRIB_CHILDREN          = 0x01000
    FAF_ATTRIB_NO_HIDDEN         = 0x02000
    FAF_FOLDERS_ONLY             = 0x04000
    FAF_NO_HIDDEN_SYS_ROMMODULES = 0x08000
    FAF_GETTARGET                = 0x10000

    FAF_ATTRIBUTES      = 0x01
    FAF_CREATION_TIME   = 0x02
    FAF_LASTACCESS_TIME = 0x04
    FAF_LASTWRITE_TIME  = 0x08
    FAF_SIZE_HIGH       = 0x10
    FAF_SIZE_LOW        = 0x20
    FAF_OID             = 0x40
    FAF_NAME            = 0x80

    # I have no idea what the Windows headers call this...
    FILE_NOT_FOUND  = 0x00000002
    PATH_NOT_FOUND  = 0x00000003
    CONNECTION_LOST = 0x80072775

    class CEHandle < FFI::Pointer
      extend FFI::DataConverter
      native_type :pointer

      def self.from_native(val, ctx)
        new(val.address)
      end

      def self.to_native(val, ctx)
        FFI::Pointer.new(val.address)
      end

      def initialize(handle)
        @finalizer = Finalizer.new(handle)
        ObjectSpace.define_finalizer(self, @finalizer)
        super handle
      end

      def valid?
        self != INVALID_HANDLE
      end

      def invalid?
        !valid?
      end

      def close
        @finalizer.call
      end

      class Finalizer
        def initialize(handle)
          @handle = handle
          @called = handle == INVALID_HANDLE.address
        end

        def call
          unless @called
            Native::Rapi.CeCloseHandle(FFI::Pointer.new(@handle))
            @called = true
            @handle = INVALID_HANDLE.address
          end
        end
      end
    end

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
        layout  :dwFileAttributes,  :uint,                0,
                :ftCreationTime,    FILETIME,             4,
                :ftLastAccessTime,  FILETIME,            12,
                :ftLastWriteTime,   FILETIME,            20,
                :nFileSizeHigh,     :uint,               28,
                :nFileSizeLow,      :uint,               32,
                :dwOID,             :uint,               36,
                :cFileName,         [:uint16, MAX_PATH], 40
      end

      class PROCESS_INFORMATION < FFI::Struct
        layout  :hProcess,       :pointer,
                :hThread,        :pointer,
                :dwProcessId,    :uint,
                :dwThreadId,     :uint
      end


      class CEOSVERSIONINFO < FFI::Struct
        layout  :dwOSVersionInfoSize, :uint,
                :dwMajorVersion,      :uint,
                :dwMinorVersion,      :uint,
                :dwBuildNumber,       :uint,
                :dwPlatformId,        :uint,
                :szCSDVersion,        [:uint16, 128]
      end

      attach_function :CeRapiFreeBuffer, [:pointer], :uint
      attach_function :CeRapiInitEx, [RAPIINIT.by_ref], :int
      attach_function :CeRapiUninit, [], :int
      attach_function :CeRapiGetError, [], :uint
      attach_function :CeCloseHandle, [CEHandle], :int
      attach_function :CeWriteFile, [:pointer, :pointer, :int, :pointer, :int], :int
      attach_function :CeReadFile, [:pointer, :pointer, :int, :pointer, :int], :int
      attach_function :CeRapiFreeBuffer, [:pointer], :void
      attach_function :CeGetFileAttributes, [:pointer], :uint
      attach_function :CeCreateFile, [:pointer, :uint, :int, :int, :int, :int, :int], CEHandle
      attach_function :CeCopyFile, [:pointer, :pointer, :int], :uint
      attach_function :CeDeleteFile, [:pointer], :uint
      attach_function :CeRemoveDirectory, [:pointer], :uint
      attach_function :CeGetFileAttributes, [:pointer], :uint
      attach_function :CeSetFileAttributes, [:pointer, :uint], :uint
      attach_function :CeFindFirstFile, [:pointer, CE_FIND_DATA.by_ref], :pointer
      attach_function :CeFindNextFile, [:pointer, CE_FIND_DATA.by_ref], :int
      attach_function :CeFindAllFiles, [:pointer, :uint, :pointer, :pointer], :uint
      attach_function :CeFindClose, [:pointer], :uint
      attach_function :CeCreateProcess, [:pointer, :pointer, :pointer, :pointer, :int, :int, :pointer, :pointer, :pointer, PROCESS_INFORMATION.by_ref], :uint
      attach_function :CeGetLastError, [], :uint
      attach_function :CeGetTempPath, [:int, :pointer], :int
      attach_function :CeSetFilePointer, [:pointer, :int, :pointer, :uint], :uint
      attach_function :CeSetEndOfFile, [:pointer], :uint
      attach_function :CeGetFileSize, [:pointer, :pointer], :uint
      attach_function :CeCreateDirectory, [:pointer, :pointer], :uint
      attach_function :CeGetVersionEx, [CEOSVERSIONINFO.by_ref], :uint

      attach_function :CeRegCloseKey, [:pointer], :uint
      attach_function :CeRegCreateKeyEx, [:pointer, :pointer, :uint, :pointer, :uint, :uint, :pointer, :pointer, :pointer], :uint
      attach_function :CeRegDeleteKey, [:pointer, :pointer], :uint
      attach_function :CeRegDeleteValue, [:pointer, :pointer], :uint
      attach_function :CeRegEnumKeyEx, [:pointer, :int, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :uint
      attach_function :CeRegEnumValue, [:pointer, :int, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :uint
      attach_function :CeRegOpenKeyEx, [:pointer, :pointer, :uint, :uint, :pointer], :uint
      attach_function :CeRegQueryInfoKey, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :uint
      attach_function :CeRegQueryValueEx, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :uint
      attach_function :CeRegSetValueEx, [:pointer, :pointer, :uint, :uint, :pointer, :uint], :uint
    end

    module Kernel32
      extend FFI::Library
      ffi_lib 'kernel32'
      ffi_convention :stdcall

      @blocking = true
      attach_function :WaitForSingleObject, [:pointer, :uint], :uint
      attach_function :FormatMessageW, [:uint, :pointer, :uint, :uint, :pointer, :uint, :pointer], :int
      attach_function :FormatMessageA, [:uint, :pointer, :uint, :uint, :pointer, :uint, :pointer], :int
      attach_function :CloseHandle, [:pointer], :uint
      attach_function :LocalFree, [:pointer], :pointer
    end
  end
end
