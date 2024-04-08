images_build:
	docker compose build

images_test:
	docker compose run --rm test

images_push:
	docker compose push httpbin