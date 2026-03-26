Rails.application.routes.draw do
  resources :pets
  get "health" => "health#show"
  get "up" => "rails/health#show", as: :rails_health_check
  root "health#show"
end
