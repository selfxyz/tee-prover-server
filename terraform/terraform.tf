terraform {
  required_version = ">= 1.6"
  
  backend "gcs" {
    bucket = "self-tfstates"
    prefix = "tee-prover-server"
  }
  
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }
}
