class Checkroom < ActiveRecord::Base
  validates :name, presence: true, length: {maximum: 255}
  validates :title, presence: true, length: {maximum: 255}
  validates :content, presence: true
  validates :secret, presence: true, length: {maximum: 30, message: "^is too long (maximum is 8 characters)"}
end
