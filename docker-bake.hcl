variable "TAG" {
  default = "local"
}

group "default" {
  targets = ["isomer-python", "isomer-node", "isomer-go", "isomer-dashboard"]
}

target "isomer-python" {
  context = "."
  dockerfile = "docker/isomer-python/Dockerfile"
  contexts = {
    keripy = "../keripy"
  }
  tags = ["w3c-crosswalk/isomer-python:${TAG}"]
}

target "isomer-node" {
  context = "."
  dockerfile = "docker/isomer-node/Dockerfile"
  contexts = {
    did_jwt_vc = "../did-jwt-vc"
  }
  tags = ["w3c-crosswalk/isomer-node:${TAG}"]
}

target "isomer-go" {
  context = "."
  dockerfile = "docker/isomer-go/Dockerfile"
  contexts = {
    vc_go = "../vc-go"
  }
  tags = ["w3c-crosswalk/isomer-go:${TAG}"]
}

target "isomer-dashboard" {
  context = "."
  dockerfile = "docker/isomer-dashboard/Dockerfile"
  tags = ["w3c-crosswalk/isomer-dashboard:${TAG}"]
}
