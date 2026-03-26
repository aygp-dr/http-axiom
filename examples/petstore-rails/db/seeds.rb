pets = [
  { name: "Buddy",    status: "available", photo_urls: ["https://example.com/buddy.jpg"] },
  { name: "Luna",     status: "available", photo_urls: ["https://example.com/luna.jpg"] },
  { name: "Max",      status: "pending",   photo_urls: [] },
  { name: "Whiskers", status: "sold",      photo_urls: ["https://example.com/whiskers.jpg"] },
  { name: "Rex",      status: "available", photo_urls: [] },
]

pets.each do |attrs|
  Pet.find_or_create_by!(name: attrs[:name]) do |pet|
    pet.status = attrs[:status]
    pet.photo_urls = attrs[:photo_urls]
  end
end

puts "Seeded #{Pet.count} pets"
