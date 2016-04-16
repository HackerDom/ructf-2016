class ItemsController < ApplicationController
  before_action :signed_in_user, only: [:create, :destroy, :update, :edit, :show]
  before_action :correct_user, only: [:destroy, :update, :edit]

  def show
    @item = Item.find_by(id: params[:id], user_id: current_user.id)
    redirect_to root_url unless @item
  end

  def get_all_yaml
    @item = Item.find_by(user_id: current_user.id)
    render yaml: @item
    # redirect_to root_url unless @item

  end

  def edit
    @item = Item.find_by(id: params[:id], user_id: current_user.id)
    redirect_to root_url unless @item
  end

  def create
    params = item_params
    params['user_id'] = current_user.id
    @item = Item.create(params)
    if @item.save
      flash[:success] = 'Thing created!'
      redirect_to @item
    else
      render 'static_pages/home'
    end
  end

  def update
    params = item_params
    if @item.update_attributes(params)
      flash[:success] = 'Thing update!'
      redirect_to @item
    else
      render 'static_pages/home'
    end
  end

  def destroy
    @item.destroy
    redirect_to root_url
  end

  private

  def correct_user
    @item = Item.find_by(id: params[:id])
    redirect_to root_url unless current_user?(@item.user)
  end

  def item_params
    params.require(:item).permit!
  end

end