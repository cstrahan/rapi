require 'rapi'

describe RAPI do
  context "when connected" do
    def tmp(parts=[])
      File.join(RAPI.tmp, "rapi_test_dir", *parts)
    end

    before do
      RAPI.connect unless RAPI.connected?
      RAPI.rm_rf(tmp) #rescue nil
    end


    it "should be connected" do
      RAPI.connected?.should be_true
    end

    describe "#search" do
      it "should find files" do
	RAPI.search('*').size.should be > 0
      end
    end

    it "should be able to disconnect" do
      RAPI.disconnect
      RAPI.connected?.should be_false
    end

    describe "#exist?" do
      it "should return true when file exists" do
	RAPI.exist?("").should be_true
      end

      it "should return false when file doesn't exist" do
	RAPI.exist?("*").should be_false
      end
    end

    describe "#mkdir" do
      it "should create folder when folder does not exist" do
	RAPI.mkdir(tmp)
	RAPI.exist?(tmp).should be_true
      end

      it "should raise exception when folder does exist" do
	lambda { RAPI.mkdir("") }.should raise_error(RAPI::RAPIError)
      end
    end

    describe "#delete" do
      it "should delete folder when folder does exist" do
	RAPI.mkdir(tmp)

	RAPI.delete(tmp)

	RAPI.exists?(tmp).should be_false
      end

      it "should delete file when file does exist" do
	RAPI.mkdir(tmp)
	RAPI.open(tmp("tempfile"), "w") { }

	RAPI.rm_rf(tmp)

	RAPI.exists?(tmp("tempfile")).should be_false
      end

      it "should raise exception when path does not exist" do
	lambda { RAPI.mkdir("") }.should raise_error(RAPI::RAPIError)
      end
    end
  end
end
