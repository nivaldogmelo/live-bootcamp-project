# Create a new Web Droplet in the nyc2 region
resource "digitalocean_droplet" "web" {
  image  = "ubuntu-22-04-x64"
  name   = "rust-live-bootcamp"
  region = "nyc1"
  size   = "s-1vcpu-1gb"
}
