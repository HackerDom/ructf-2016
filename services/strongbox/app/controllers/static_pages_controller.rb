class StaticPagesController < ApplicationController
  before_action :signed_in_user, only: :home

  def home
    @things = Thing.where(user_id: current_user.id).all
    @thing_new = current_user.things.build
  end
end
