IMAGE      := packetfence-android-agent-build
USER_SPEC  := $(shell id -u):$(shell id -g)
CACHE_DIR  := $(CURDIR)/.gradle-cache

DOCKER_RUN = docker run --rm \
	--user $(USER_SPEC) \
	-v "$(CURDIR)":/workspace \
	-v "$(CACHE_DIR)":/gradle \
	-e GRADLE_USER_HOME=/gradle \
	-e HOME=/tmp \
	-w /workspace \
	$(IMAGE)

.PHONY: help docker-image assembleDebug minifyReleaseWithR8 verify-no-apache-http lint test all clean

help:
	@echo "Targets:"
	@echo "  docker-image          Build the local build container (one-time / on Dockerfile change)."
	@echo "  assembleDebug         ./gradlew clean assembleDebug inside the container."
	@echo "  minifyReleaseWithR8   ./gradlew minifyReleaseWithR8 inside the container."
	@echo "  verify-no-apache-http minifyReleaseWithR8 + scan the release DEX for org.apache.http (CI guard)."
	@echo "  lint                  ./gradlew lint inside the container."
	@echo "  test                  ./gradlew test inside the container."
	@echo "  all                   assembleDebug + verify-no-apache-http + lint + test (mirrors CI)."
	@echo "  clean                 Remove build/ and the local gradle cache."

docker-image:
	docker build -t $(IMAGE) .

$(CACHE_DIR):
	mkdir -p $(CACHE_DIR)

assembleDebug: docker-image $(CACHE_DIR)
	$(DOCKER_RUN) ./gradlew clean assembleDebug

minifyReleaseWithR8: docker-image $(CACHE_DIR)
	$(DOCKER_RUN) ./gradlew minifyReleaseWithR8

verify-no-apache-http: minifyReleaseWithR8
	@DEX_DIR=build/intermediates/dex/release/minifyReleaseWithR8; \
	total=0; \
	scanned=0; \
	for dex in $$DEX_DIR/*.dex; do \
	  [ -f "$$dex" ] || continue; \
	  scanned=$$((scanned + 1)); \
	  count=$$(LC_ALL=C grep -a -o "org/apache/http" "$$dex" | wc -l); \
	  echo "$$dex: $$count org.apache.http references"; \
	  total=$$((total + count)); \
	done; \
	if [ "$$scanned" -eq 0 ]; then \
	  echo "FAIL: no DEX files found under $$DEX_DIR (did minifyReleaseWithR8 run?)"; \
	  exit 1; \
	fi; \
	if [ "$$total" -ne 0 ]; then \
	  echo "FAIL: $$total org.apache.http references in release DEX (16 KB-page regression)"; \
	  exit 1; \
	fi; \
	echo "OK: 0 org.apache.http references in release DEX."

lint: docker-image $(CACHE_DIR)
	$(DOCKER_RUN) ./gradlew lint

test: docker-image $(CACHE_DIR)
	$(DOCKER_RUN) ./gradlew test

all: assembleDebug verify-no-apache-http lint test

clean:
	rm -rf build $(CACHE_DIR)
