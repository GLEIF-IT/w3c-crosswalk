variable "TAG" {
  default = "local"
}

group "default" {
  targets = ["isomer-python", "isomer-node", "isomer-go", "isomer-dashboard"]
}

target "isomer-python" {
  context = "."
  dockerfile = "docker/isomer-python/Dockerfile"
  tags = ["w3c-crosswalk/isomer-python:${TAG}"]
}

target "isomer-node" {
  context = "."
  dockerfile = "docker/isomer-node/Dockerfile"
  tags = ["w3c-crosswalk/isomer-node:${TAG}"]
}

target "isomer-go" {
  context = "."
  dockerfile = "docker/isomer-go/Dockerfile"
  tags = ["w3c-crosswalk/isomer-go:${TAG}"]
}

target "isomer-dashboard" {
  context = "."
  dockerfile = "docker/isomer-dashboard/Dockerfile"
  tags = ["w3c-crosswalk/isomer-dashboard:${TAG}"]
}
