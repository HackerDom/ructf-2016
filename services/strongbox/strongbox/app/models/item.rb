class Item < ActiveRecord::Base
  belongs_to :user
  validates :user_id, presence: true

  validates :title, presence: true, length: {maximum: 255}
  validates :content, presence: true
end
