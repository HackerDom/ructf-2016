class ItemsController < ApplicationController
  before_action :signed_in_user, only: [:create, :destroy, :update, :edit, :show]
  before_action :correct_user, only: [:destroy, :update, :edit, :show]

  def show
  end

  def edit
  end

  def create
    item_param = item_params
    item_param['user_id'] = current_user.id

    @item = Item.create(item_param)
    if @item.save
      flash[:success] = 'Thing created!'
      redirect_to @item
    else
      render 'static_pages/home'
    end
  end

  def update
    @id = params[:id].scan /\w/
    @item = Item.update(@id, item_params)
    if !(@item.nil?)
      flash[:success] = 'Thing update!'
      redirect_to @item
    else
      render 'static_pages/home'
    end
  end

  def destroy
    @item = Item.find_by(id: params[:id])
    @item.destroy
    redirect_to root_url
  end

  private

  def correct_user
    @item = Item.find(params[:id])
    redirect_to '/strongbox?type=private' unless current_user?(@item.user)
  end

  def item_params
    if params.require(:item).kind_of?(Array)
      params.require(:item).map do |u|
        ActionController::Parameters.new(u.to_hash).permit!
      end
    else
      params.require(:item).permit!
    end
  end
end