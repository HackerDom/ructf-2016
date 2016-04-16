class CreateCheckrooms < ActiveRecord::Migration
  def change
    create_table :checkrooms do |t|
      t.string :name
      t.string :title
      t.string :content
      t.string :secret

      t.timestamps null: false
    end
  end
end
