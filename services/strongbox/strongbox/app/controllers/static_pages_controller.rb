class StaticPagesController < ApplicationController
  def home
  end

  def type
    params[:type].gsub!(/[\/]/, '')
    params[:type].gsub!('..', '.')
    if params[:type] == 'private'
      if signed_in?
        @items = Item.where(user_id: current_user.id).all
        @item_new = Item.new
        render params[:type]
      else
        store_location
        redirect_to signin_url, notice: "Please sign in."
      end
    elsif params[:type] == 'public'
      @items = Checkroom.all
      @item_new = Checkroom.new
      render params[:type]
    end
  end
end
