require 'spec_helper'
require 'rails_helper'


describe "Static pages" do
  subject { page }

  describe "Index page" do
    before { visit index_path }
    it { should have_content('Home') }
    it { should have_title("Index") }
    it { should have_http_status(200) }
  end

end