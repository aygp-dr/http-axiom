class CreatePets < ActiveRecord::Migration[8.1]
  def change
    create_table :pets do |t|
      t.string :name, null: false
      t.string :status, null: false, default: "available"
      t.text :photo_urls
      t.timestamps
    end
  end
end
