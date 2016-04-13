Rails.application.routes.draw do


  get 'users/new'

  root 'static_pages#home'

  # Static
  match '/index', to: 'static_pages#home', via: 'get'

  # User
  resources :users
  match '/signup', to: 'users#new', via: 'get'

  #Auth
  resources :sessions, only: [:new, :create, :destroy]
  match '/signin', to: 'sessions#new', via: 'get'
  match '/signout', to: 'sessions#destroy', via: 'delete'

  #Things
  resources :things, only: [:create, :destroy, :edit, :update, :show]

end
