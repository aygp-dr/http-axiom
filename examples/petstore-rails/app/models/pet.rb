class Pet < ApplicationRecord
  validates :name, presence: true
  validates :status, inclusion: { in: %w[available pending sold] }

  def photo_urls=(value)
    super(Array(value).to_json)
  end

  def photo_urls
    JSON.parse(super || "[]")
  rescue JSON::ParserError
    []
  end
end
