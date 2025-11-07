provider "google" {
  project = var.project_id
  region  = "us-west1"
}

provider "google-beta" {
  project = var.project_id
  region  = "us-west1"
}
