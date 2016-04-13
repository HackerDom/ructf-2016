class ThingsController < ApplicationController
  before_action :signed_in_user, only: [:create, :destroy, :update, :edit, :show]
  before_action :correct_user, only: [:destroy, :update, :edit]

  def show
    @thing = Thing.find_by(id: params[:id], user_id: current_user.id)
    redirect_to root_url unless @thing
  end

  def edit
    @thing = Thing.find_by(id: params[:id], user_id: current_user.id)
    redirect_to root_url unless @thing
  end

  def create
    params = thing_params
    params['user_id'] = current_user.id
    @thing = Thing.create(params)
    if @thing.save
      flash[:success] = 'Thing created!'
      redirect_to root_url
    else
      render 'static_pages/home'
    end
  end

  def update
    params = thing_params
    if @thing.update_attributes(params)
      flash[:success] = 'Thing update!'
      redirect_to @thing
    else
      render 'static_pages/home'
    end
  end

  def destroy
    @thing.destroy
    redirect_to root_url
  end

  private

  def correct_user
    @thing = Thing.find_by(id: params[:id])
    redirect_to root_url unless current_user?(@thing.user)
  end

  def thing_params
    params.require(:thing).permit(:content, :title, :user_id)
  end

end