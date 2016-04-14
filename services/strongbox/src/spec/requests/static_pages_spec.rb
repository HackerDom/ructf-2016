require 'rails_helper'
require 'spec_helper'

describe "Static pages" do
  subject { page }
  describe "Home page" do
    before { visit root_path }

    it { should have_content('StaticPages#home') }

  end
end
