class StaticPagesController < ApplicationController
  # before_action :signed_in_user, only: :home

  def home
  end

  def type
    params[:type].gsub!(/[\/]/, '')
    params[:type].gsub!('..', '.')
    if params[:type] == 'private'
      signed_in_user
      @items = Item.where(user_id: current_user.id).all
      @item_new = Item.new
    elsif params[:type] == 'public'
      @items = Checkroom.all
      @item_new = Checkroom.new
    end
    render params[:type]
  end
end
