Rails.application.routes.draw do

  get 'users/new'

  root 'static_pages#home'

  # Static
  match '/index', to: 'static_pages#home', via: 'get'

  match '/strongbox/', to: 'static_pages#type', via: 'get'

  # User
  resources :users
  match '/signup', to: 'users#new', via: 'get'

  #Auth
  resources :sessions, only: [:new, :create, :destroy]
  match '/signin', to: 'sessions#new', via: 'get'
  match '/signout', to: 'sessions#destroy', via: 'delete'

  #Items
  resources :items, only: [:create, :destroy, :edit, :update, :show]
  match '/items/get_all_yaml', to: 'item#get_all_yaml', via: 'get'

  #Checkroom
  resources :checkrooms, only: [:new, :create, :show]
  match '/checkrooms/:id', to: 'checkrooms#show', via: 'post'
  # match '/checkrooms/login', to: 'checkrooms#set_secret', via: 'post'
end
