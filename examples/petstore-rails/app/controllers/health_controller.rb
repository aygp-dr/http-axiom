class HealthController < ApplicationController
  def show
    render json: {
      status: "ok",
      version: "0.0.1",
      database: database_connected?
    }
  end

  private

  def database_connected?
    ActiveRecord::Base.connection.active?
  rescue StandardError
    false
  end
end
