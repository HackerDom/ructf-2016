class StaticPagesController < ApplicationController
  def home
  end

  def type
    @ren = true
    if !params[:type].nil?
      if params[:type] == 'private'
        if signed_in?
          @items = Item.where(user_id: current_user.id).all
          @item_new = Item.new
        else
          store_location
          @ren = false
        end
      elsif params[:type] == 'public'
        @items = Checkroom.all
        @item_new = Checkroom.new
      end
      if @ren
        render params[:type]
      else
        redirect_to signin_url, notice: "Please sign in."
      end
    else
      redirect_to root_path
    end

  end
end
