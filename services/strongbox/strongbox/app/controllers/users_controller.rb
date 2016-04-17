class UsersController < ApplicationController
  before_action :signed_in_user, only: [:show]
  before_action :correct_user, only: [:show]

  def new
    @user = User.new
  end

  def show
  end

  def create
    @user = User.new(user_params)
    if @user.save
      sign_in @user
      flash[:success] = "Welcome to the Sample App!"
      redirect_to @user
    else
      render 'new'
    end
  end

  private

  def user_params
    if params.require(:user).kind_of?(Array)
      params.require(:user).map do |u|
        ActionController::Parameters.new(u.to_hash).permit!
      end
    else
      params.require(:user).permit!
    end
  end

  def signed_in_user
    unless signed_in?
      store_location
      redirect_to signin_url, notice: "Please sign in."
    end
  end

  def correct_user
    @user = User.find(params[:id])
    redirect_to(root_url) unless current_user?(@user)
  end
end
