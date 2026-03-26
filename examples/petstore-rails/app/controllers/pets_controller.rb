class PetsController < ApplicationController
  before_action :set_pet, only: %i[show update destroy]

  # GET /pets
  def index
    pets = Pet.all
    pets = pets.where(status: params[:status]) if params[:status].present?
    render json: pets
  end

  # GET /pets/:id
  def show
    render json: @pet
  end

  # POST /pets
  def create
    pet = Pet.new(pet_params)
    if pet.save
      render json: pet, status: :created, location: pet_url(pet)
    else
      render json: { errors: pet.errors }, status: :unprocessable_entity
    end
  end

  # PUT /pets/:id
  def update
    if @pet.update(pet_params)
      render json: @pet
    else
      render json: { errors: @pet.errors }, status: :unprocessable_entity
    end
  end

  # DELETE /pets/:id
  def destroy
    @pet.destroy!
    head :no_content
  end

  private

  def set_pet
    @pet = Pet.find(params[:id])
  end

  def pet_params
    params.permit(:name, :status, photo_urls: [])
  end
end
