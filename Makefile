# Copyright 2024 Canonical Ltd.
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

BIN_DIR := $(CURDIR)/_bin

define BUILD_TARGETS
	generate-ood-portal
endef

define go_build
	@echo "Building ${PACKAGE}"
	@mkdir -p ${BIN_DIR}
	CGO_ENABLED=0 go build -o ${BIN_DIR} -v ${PACKAGE}
endef

all: build test

.PHONY: build
build: $(BUILD_TARGETS)
## build: build target CLI applications under $PWD/_bin

.PHONY: generate-ood-portal
generate-ood-portal: PACKAGE = github.com/charmed-hpc/ood-portal-generator/cmd/generate-ood-portal
generate-ood-portal:
	$(go_build)

.PHONY: test
test:
## test: run unit tests for project
	go test -coverprofile=coverage.out ./...

.PHONY: clean
clean:
## clean: clean the cache, test cache, and build directory
	go clean -x --cache --testcache
	go clean -x -r ./...
	rm -rf *.out
	rm -rf ${BIN_DIR}

.PHONY: fmt
fmt:
## fmt: reformat Go source files using gofmt
	go fmt -x ./...

.PHONY: deps
deps:
## deps: install project dependencies
	go mod download -x

.PHONY: help
help:
	@echo "Usage: \n"
	@sed -n 's/^## //p' ${MAKEFILE_LIST} | sort | column -t -s ':' |  sed -e 's/^/ /'
