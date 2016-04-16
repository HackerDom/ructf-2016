class CheckroomsController < ApplicationController
  def new
    @checkroom = Checkroom.new
  end

  def create
    secret = checkroom_params['secret']
    salt = SecureRandom.urlsafe_base64
    random_number = Random.new.rand(5..15)
    checkroom_params['secret'] = salt[0..random_number] + secret +salt[random_number+1..-1]
    @checkroom = Checkroom.new(checkroom_params)
    if @checkroom.save
      flash[:success] = "Checkroom create!"
      redirect_to '/strongbox/public'
    else
      render 'new'
    end
  end

  def show
    @checkroom = Checkroom.find(params[:id])
    if check_secret
      render 'show'
    else
      render 'login'
    end
  end

  private

  def checkroom_params
    params.require(:checkroom).permit!
  end

  def check_secret
    unless params[:secret].nil?
      if params[:secret].length == (@checkroom['secret'].length - 22)
        return @checkroom.secret.scan(params[:secret]).size
      end
    end
    false
  end

end


